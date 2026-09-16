rule _20160921_1c0508ced9fad1614d80fce90a3209ed_20160921_da4ec6dae2ec_3472 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c0508ced9fad1614d80fce90a3209ed.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e27406e32c891781b5403c718c4f32d67f6580cf6f952a30d0c6452ab9775a4c"
    hash2       = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"

  strings:
    $s1 = "on f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"" ascii
    $s2 = "\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Rh\";})(),(function f" ascii
    $s3 = "(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"YTp\";" ascii
    $s4 = "eturn \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"SGs\";})()" ascii
    $s5 = "),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nv\";})(),(function f000(){" ascii
    $s6 = "nction f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mt\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}