rule sig_20160525_219ba42d9002f09c34f9a734e9b3f1c5 {
  meta:
    description = "datamaliciousorder - file 20160525_219ba42d9002f09c34f9a734e9b3f1c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18ff22ce77dffc25dac8f11d0f816f6fc6f7f47acf127d2c35d31aaddf9bfeaa"

  strings:
    $s1 = "oitcnuf\\n;\"e6x\\\\uR\" = deerdp rav\\n;\"peel35x\\\\\" = sdnetp rav\\n;\"ec6x\\\\\" = tsilslianbmuhtop rav\\n;\"t76x\\\\n\" = " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}