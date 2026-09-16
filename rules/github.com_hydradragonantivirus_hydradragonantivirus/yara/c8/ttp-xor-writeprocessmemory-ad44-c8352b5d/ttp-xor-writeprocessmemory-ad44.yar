rule TTP_XOR_WriteProcessMemory_ad44 {
  strings:
    $key_ad44 = { fa 36 [2] c8 14 [2] ce 21 [2] e0 21 [2] df 3d }

  condition:
    any of them
}