rule sig_20161207_9376c4522b2244e6469abf27cf841bd2 {
  meta:
    description = "datamaliciousorder - file 20161207_9376c4522b2244e6469abf27cf841bd2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f91db9d93ad257138acd9271cb52dd717f6de40b68a642eff2babab2597039d2"

  strings:
    $s1 = "var vSw2 = new Function(\"vWw3\", '{var vCi0 = new Date();vCi0[\"setUTCFullYear\"](\"2003\");if (vCi0.getUTCFullYear().toString(" ascii
    $s2 = "var vSw2 = new Function(\"vWw3\", '{var vCi0 = new Date();vCi0[\"setUTCFullYear\"](\"2003\");if (vCi0.getUTCFullYear().toString(" ascii
    $s3 = "var vPg0 = new Function(\"vWw3\", '{return vWw3.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vRc6 = vWw3.split(\"###\"); return vRc6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}