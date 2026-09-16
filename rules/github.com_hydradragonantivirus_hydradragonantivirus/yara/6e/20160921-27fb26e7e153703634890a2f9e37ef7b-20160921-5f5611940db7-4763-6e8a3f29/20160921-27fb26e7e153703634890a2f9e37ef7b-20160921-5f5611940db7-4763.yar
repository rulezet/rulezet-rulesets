rule _20160921_27fb26e7e153703634890a2f9e37ef7b_20160921_5f5611940db7_4763 {
  meta:
    description = "datamaliciousorder - from files 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_5f5611940db748f8f47ad6671e45ac27.js, 20160921_cff7808833d9e819d4a4f10450848a81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash2       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"
    hash3       = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"

  strings:
    $s1 = "){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})" ascii
    $s2 = "n\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"EZu\";})(),(functio" ascii
    $s3 = "n \"KDh\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(fun" ascii
    $s4 = "n \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(func" ascii
    $s5 = " f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}