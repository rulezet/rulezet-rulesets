rule sig_20161002_b8ad09a8c80d75bcb975e03089a4f430 {
  meta:
    description = "datamaliciousorder - file 20161002_b8ad09a8c80d75bcb975e03089a4f430.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbccf64cb9068e7db8f6f068a2207fd38eb157e7b850d80a1335337d42575262"

  strings:
    $s1 = "ZF0UE7PBAJF6EFDYF0RBBLF5FF0ZF9UFDNFAIBAVE4RFCKE4EABZF2TA9OA0IA4CA7X\",YNWJR),false); " fullword ascii

  condition:
    uint16(0) == 0x2020 and
    all of them
}