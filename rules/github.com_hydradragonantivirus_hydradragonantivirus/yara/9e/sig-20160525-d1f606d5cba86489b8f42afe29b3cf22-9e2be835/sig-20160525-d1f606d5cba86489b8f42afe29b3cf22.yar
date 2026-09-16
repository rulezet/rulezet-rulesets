rule sig_20160525_d1f606d5cba86489b8f42afe29b3cf22 {
  meta:
    description = "datamaliciousorder - file 20160525_d1f606d5cba86489b8f42afe29b3cf22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d39d181e2529b67a2aab508bc092fa070aeb4b4fb920db84edd5f64957754168"

  strings:
    $s1 = " rav\\n;\"tc6x\\\\\" = eixodc rav\\n;)2(]\"tAra\"+\"86x\\\\\"+\"c\"[imb = gsmc rav;\"kd5B\" = imb rav\\n;\"ne2x\\\\\" = dnenoisi" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}