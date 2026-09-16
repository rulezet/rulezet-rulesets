rule TTP_XOR_WriteProcessMemory_ad46 {
  strings:
    $key_ad46 = { fa 34 [2] c8 16 [2] ce 23 [2] e0 23 [2] df 3f }

  condition:
    any of them
}