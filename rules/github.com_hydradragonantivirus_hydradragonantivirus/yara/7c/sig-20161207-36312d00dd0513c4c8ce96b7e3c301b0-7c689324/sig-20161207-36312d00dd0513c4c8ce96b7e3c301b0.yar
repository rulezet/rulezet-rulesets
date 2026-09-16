rule sig_20161207_36312d00dd0513c4c8ce96b7e3c301b0 {
  meta:
    description = "datamaliciousorder - file 20161207_36312d00dd0513c4c8ce96b7e3c301b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d18727511d530069c6f98a902cf6d0993bc5178acdd47c60258fd1162dfaeb5e"

  strings:
    $s1 = "var vDc3 = new Function(\"vYCm5\", '{var vUKo1 = new Date();vUKo1[\"setUTCFullYear\"](\"2003\");if (vUKo1.getUTCFullYear().toStr" ascii
    $s2 = "var vDc3 = new Function(\"vYCm5\", '{var vUKo1 = new Date();vUKo1[\"setUTCFullYear\"](\"2003\");if (vUKo1.getUTCFullYear().toStr" ascii
    $s3 = "var vMp9 = new Function(\"vYCm5\", '{return vYCm5.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vLa6 = vYCm5.split(\"###\"); return vLa6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}