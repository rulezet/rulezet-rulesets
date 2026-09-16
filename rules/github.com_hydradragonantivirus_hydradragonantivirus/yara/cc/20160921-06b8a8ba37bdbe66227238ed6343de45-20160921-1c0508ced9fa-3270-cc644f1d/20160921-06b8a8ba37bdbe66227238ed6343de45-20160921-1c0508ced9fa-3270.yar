rule _20160921_06b8a8ba37bdbe66227238ed6343de45_20160921_1c0508ced9fa_3270 {
  meta:
    description = "datamaliciousorder - from files 20160921_06b8a8ba37bdbe66227238ed6343de45.js, 20160921_1c0508ced9fad1614d80fce90a3209ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49865219ca3278a1a02bfd25fc25cac90e7685a0b5083a98acee0c82fc74d77b"
    hash2       = "e27406e32c891781b5403c718c4f32d67f6580cf6f952a30d0c6452ab9775a4c"

  strings:
    $s1 = "\"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(funct" ascii
    $s2 = "nction f000(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){retur" ascii
    $s3 = "(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";}" ascii
    $s4 = " f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"L" ascii
    $s5 = "f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc" ascii
    $s6 = "){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}