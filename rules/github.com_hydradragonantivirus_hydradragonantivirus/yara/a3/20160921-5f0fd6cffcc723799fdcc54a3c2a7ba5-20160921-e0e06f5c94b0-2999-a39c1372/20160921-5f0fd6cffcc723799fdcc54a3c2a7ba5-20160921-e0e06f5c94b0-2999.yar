rule _20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5_20160921_e0e06f5c94b0_2999 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js, 20160921_e0e06f5c94b0cde962f3e4c452e69af8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"
    hash2       = "c9140c7affc44d690abfb95dc146d3e298e2cfddacedfee85549119f368d56d1"

  strings:
    $s1 = "unction f000(){return \"Sq\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s2 = "00(){return \"IPu\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv" ascii
    $s3 = "})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f00" ascii
    $s4 = "Db\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"NYh\";})(),(functi" ascii
    $s5 = "{return \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"DIa\";})(" ascii
    $s6 = "nction f000(){return \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"Qz\";})(),(function f000(){retur" ascii
    $s7 = "0(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DYs\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}