rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160921_334dc22c3620_4187 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160921_334dc22c3620386c4119de547e0c0f38.js, 20160921_ebd0ee36b6a55e4cbf431d8fa9a2aea3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "a69d8e08a2b4320b4183bfad7a1baa8fc49b7361116aeb9e3a542ae416cd93d5"
    hash3       = "f2f666db493211ee6edb824e429f601fccdbf25cd3cc08bc16ad31fdf23c4636"

  strings:
    $s1 = "eturn \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})()," ascii
    $s2 = "000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\"" ascii
    $s3 = " \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(fu" ascii
    $s4 = "00(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\"" ascii
    $s5 = "g\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}