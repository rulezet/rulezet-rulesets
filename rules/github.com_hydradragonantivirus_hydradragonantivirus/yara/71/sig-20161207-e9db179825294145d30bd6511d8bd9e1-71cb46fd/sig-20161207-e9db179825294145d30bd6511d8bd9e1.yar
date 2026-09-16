rule sig_20161207_e9db179825294145d30bd6511d8bd9e1 {
  meta:
    description = "datamaliciousorder - file 20161207_e9db179825294145d30bd6511d8bd9e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c981c65a3ecd2f22398a070e7ae2116e8d7f84feee424a46620e5fe449c1195"

  strings:
    $s1 = "var vDa8 = new Function(\"vCLu3\", '{var vIJp1 = new Date();vIJp1[\"setUTCFullYear\"](\"2003\");if (vIJp1.getUTCFullYear().toStr" ascii
    $s2 = "var vDa8 = new Function(\"vCLu3\", '{var vIJp1 = new Date();vIJp1[\"setUTCFullYear\"](\"2003\");if (vIJp1.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vPe3 = vCLu3.split(\"###\"); return vPe3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vUi3 = new Function(\"vCLu3\", '{return vCLu3.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}