rule _20160921_18cdf3dec8ac4b7697e775bc56ddeba9_20160921_fff847efa0ea_1667 {
  meta:
    description = "datamaliciousorder - from files 20160921_18cdf3dec8ac4b7697e775bc56ddeba9.js, 20160921_fff847efa0eaa326a0aad4d2fc81d41e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a1aa090c906360f52952b29d512b8c450c7e8c8cff28bc6fded6af15377b37c"
    hash2       = "93f868a10878cb41f305e28c8802778903c99b84a1bc0647a0c2c78fd6310577"

  strings:
    $s1  = "ction f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return" ascii
    $s2  = "ion f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii
    $s3  = "return \"SGs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})()," ascii
    $s4  = "n \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(f" ascii
    $s5  = "Lk\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(functio" ascii
    $s6  = "nction f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Nx\";})(),(function f000(){retur" ascii
    $s7  = "n \"Wh\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IPu\";})(),(fun" ascii
    $s8  = " \"Uo\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s9  = "0(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";" ascii
    $s10 = "000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s11 = "){return \"QDg\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}