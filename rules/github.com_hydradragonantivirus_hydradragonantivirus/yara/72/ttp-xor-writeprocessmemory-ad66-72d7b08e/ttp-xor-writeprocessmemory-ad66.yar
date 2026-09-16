rule TTP_XOR_WriteProcessMemory_ad66 {
  strings:
    $key_ad66 = { fa 14 [2] c8 36 [2] ce 03 [2] e0 03 [2] df 1f }

  condition:
    any of them
}