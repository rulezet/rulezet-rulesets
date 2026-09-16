rule sig_20161207_09919dbac66c99ad752f4f059e907c3b {
  meta:
    description = "datamaliciousorder - file 20161207_09919dbac66c99ad752f4f059e907c3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2878b87ef0119ec312aac3eb999a9ab195dbbe34d0d0166b73dd81e30820f3c6"

  strings:
    $s1 = "var vUEr7 = new Function(\"vXk2\", '{var vMFv6 = new Date();vMFv6[\"setUTCFullYear\"](\"2003\");if (vMFv6.getUTCFullYear().toStr" ascii
    $s2 = "var vUEr7 = new Function(\"vXk2\", '{var vMFv6 = new Date();vMFv6[\"setUTCFullYear\"](\"2003\");if (vMFv6.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vIn7 = vXk2.split(\"###\"); return vIn7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vGNg5 = new Function(\"vXk2\", '{return vXk2.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}