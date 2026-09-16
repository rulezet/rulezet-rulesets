rule sig_20160525_19d8ce93287978702e2079acf116c182 {
  meta:
    description = "datamaliciousorder - file 20160525_19d8ce93287978702e2079acf116c182.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51743d3b91ae0309235809b81d8810e6e76eb59a48ac390f3b1e0f6aaecf0871"

  strings:
    $s1 = "v\\n;\"aer34x\\\\\" = rerednert rav\\n;\"56x\\\\t\" = imt rav\\n;\"36x\\\\ejbf4x\\\\\" = eixodu rav\\n;\"47x\\\\\" = gsmu rav\\n" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}