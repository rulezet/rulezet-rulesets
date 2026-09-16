rule sig_20161207_f1e189f602e940bcf4bee6739c71bebd {
  meta:
    description = "datamaliciousorder - file 20161207_f1e189f602e940bcf4bee6739c71bebd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7cd023efb5b812f4c629458257f4b83dfb39b91e3adbd14acbfee2fc1f64078"

  strings:
    $s1 = "var vIPz9 = new Function(\"vSRg1\", '{var vWc4 = new Date();vWc4[\"setUTCFullYear\"](\"2003\");if (vWc4.getUTCFullYear().toStrin" ascii
    $s2 = "var vIPz9 = new Function(\"vSRg1\", '{var vWc4 = new Date();vWc4[\"setUTCFullYear\"](\"2003\");if (vWc4.getUTCFullYear().toStrin" ascii
    $s3 = "var vRs9 = new Function(\"vSRg1\", '{return vSRg1.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vEd9 = vSRg1.split(\"###\"); return vEd9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}