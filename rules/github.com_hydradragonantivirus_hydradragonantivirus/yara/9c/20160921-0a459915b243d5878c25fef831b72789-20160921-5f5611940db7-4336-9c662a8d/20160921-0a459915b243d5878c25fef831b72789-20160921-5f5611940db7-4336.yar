rule _20160921_0a459915b243d5878c25fef831b72789_20160921_5f5611940db7_4336 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a459915b243d5878c25fef831b72789.js, 20160921_5f5611940db748f8f47ad6671e45ac27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f8d1944044e8a67a527f50e4aeb45e9358929b0d0f7aaf1730d2782f07a09de"
    hash2       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"

  strings:
    $s1 = "(),(function f000(){return \"RVb\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(" ascii
    $s2 = "\"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s3 = "urn \"DNa\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s4 = "f000(){return \"Vj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn" ascii
    $s5 = "rn \"NYh\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}