rule sig_20161207_f4023ac9d802c1f97b952c9ea31da375 {
  meta:
    description = "datamaliciousorder - file 20161207_f4023ac9d802c1f97b952c9ea31da375.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30def5e63c0969849fe7ff94a7aced123371809d524f8131f653019630d123e4"

  strings:
    $s1 = "var vKVr9 = new Function(\"vXe0\", '{var vIUi5 = new Date();vIUi5[\"setUTCFullYear\"](\"2003\");if (vIUi5.getUTCFullYear().toStr" ascii
    $s2 = "var vKVr9 = new Function(\"vXe0\", '{var vIUi5 = new Date();vIUi5[\"setUTCFullYear\"](\"2003\");if (vIUi5.getUTCFullYear().toStr" ascii
    $s3 = "var vUWr6 = new Function(\"vXe0\", '{return vXe0.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vYXj1 = vXe0.split(\"###\"); return vYXj1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}