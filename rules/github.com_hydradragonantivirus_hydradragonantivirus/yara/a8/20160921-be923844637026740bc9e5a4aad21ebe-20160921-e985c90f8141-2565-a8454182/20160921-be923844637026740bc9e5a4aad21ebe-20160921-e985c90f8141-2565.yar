rule _20160921_be923844637026740bc9e5a4aad21ebe_20160921_e985c90f8141_2565 {
  meta:
    description = "datamaliciousorder - from files 20160921_be923844637026740bc9e5a4aad21ebe.js, 20160921_e985c90f8141417e484ad0056c9b809c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"
    hash2       = "513b80dc65238dcfcb80f0e8e4f456645bf345b2dde46805b001c07bc579d4c9"

  strings:
    $s1 = " \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s2 = "eturn \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})()" ascii
    $s3 = "\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Lp\";})(),(function " ascii
    $s4 = "0(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Km\";" ascii
    $s5 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Oh\";})(),(function f000" ascii
    $s6 = "0(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";}" ascii
    $s7 = "f000(){return \"Qa\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GG" ascii
    $s8 = " f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"RP" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}