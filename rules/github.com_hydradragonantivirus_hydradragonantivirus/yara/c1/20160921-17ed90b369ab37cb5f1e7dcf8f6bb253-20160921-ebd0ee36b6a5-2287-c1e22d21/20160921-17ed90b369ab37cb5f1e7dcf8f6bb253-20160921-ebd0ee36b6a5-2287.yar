rule _20160921_17ed90b369ab37cb5f1e7dcf8f6bb253_20160921_ebd0ee36b6a5_2287 {
  meta:
    description = "datamaliciousorder - from files 20160921_17ed90b369ab37cb5f1e7dcf8f6bb253.js, 20160921_ebd0ee36b6a55e4cbf431d8fa9a2aea3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81de0ae14e0c288b697a0e3c7f3ced9b68b8377e75dff5322d654841e642a8a7"
    hash2       = "f2f666db493211ee6edb824e429f601fccdbf25cd3cc08bc16ad31fdf23c4636"

  strings:
    $s1 = "a\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function" ascii
    $s2 = "000(){return \"RLk\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s3 = "f000(){return \"PTi\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"I" ascii
    $s4 = "{return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"SGs\";})" ascii
    $s5 = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){retu" ascii
    $s6 = "0(){return \"ZFe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";" ascii
    $s7 = "),(function f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"DNa\";})(),(function f000(" ascii
    $s8 = ")(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"DNa\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}