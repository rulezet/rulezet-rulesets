rule sig_20161207_fadc2527d889ad80c295aced692fe62c {
  meta:
    description = "datamaliciousorder - file 20161207_fadc2527d889ad80c295aced692fe62c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6887053c38a523d7e02be46c0985f357c77773ed934831d50d318d2b6f0a4db"

  strings:
    $s1 = "var vJYp1 = new Function(\"vWKn9\", '{var vHm0 = new Date();vHm0[\"setUTCFullYear\"](\"2003\");if (vHm0.getUTCFullYear().toStrin" ascii
    $s2 = "var vJYp1 = new Function(\"vWKn9\", '{var vHm0 = new Date();vHm0[\"setUTCFullYear\"](\"2003\");if (vHm0.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vDXd5 = vWKn9.split(\"###\"); return vDXd5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vMMt1 = new Function(\"vWKn9\", '{return vWKn9.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}