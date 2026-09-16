rule sig_20161207_93fac27373ae3ed245096410ff8c2e56 {
  meta:
    description = "datamaliciousorder - file 20161207_93fac27373ae3ed245096410ff8c2e56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "761841725758d7d977ff59c465742cb39eaaa017835462f707ff2c8277388365"

  strings:
    $s1 = "var vRn2 = new Function(\"vLi3\", '{var vGb4 = new Date();vGb4[\"setUTCFullYear\"](\"2003\");if (vGb4.getUTCFullYear().toString(" ascii
    $s2 = "var vRn2 = new Function(\"vLi3\", '{var vGb4 = new Date();vGb4[\"setUTCFullYear\"](\"2003\");if (vGb4.getUTCFullYear().toString(" ascii
    $s3 = "var vGo7 = new Function(\"vLi3\", '{return vLi3.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vSq2 = vLi3.split(\"###\"); return vSq2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}