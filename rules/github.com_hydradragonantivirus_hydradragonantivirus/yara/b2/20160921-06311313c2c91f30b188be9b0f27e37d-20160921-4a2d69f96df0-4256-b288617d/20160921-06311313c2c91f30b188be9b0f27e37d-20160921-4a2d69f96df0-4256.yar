rule _20160921_06311313c2c91f30b188be9b0f27e37d_20160921_4a2d69f96df0_4256 {
  meta:
    description = "datamaliciousorder - from files 20160921_06311313c2c91f30b188be9b0f27e37d.js, 20160921_4a2d69f96df0dd4c57fda9e63c804950.js, 20160922_92c62e47426236a3598469915ee3dcfe.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e8ad2d8de7bc2cc77c2b00b8eeb4fd7976cd68790eeb4b6bfd14ad188696ed0"
    hash2       = "786d4a5233f100c1ba7f5e820c46309247158a45ed43bd58795f05152dbaecf6"
    hash3       = "d6b6eb713cecae41143fb04e090a4809564a1837f49e53a84e27f0d3b0885df7"
    hash4       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1 = "0(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s2 = "{return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})()" ascii
    $s3 = "on f000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii
    $s4 = "nction f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vj\";})(),(function f000(){retur" ascii
    $s5 = "Lp\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}