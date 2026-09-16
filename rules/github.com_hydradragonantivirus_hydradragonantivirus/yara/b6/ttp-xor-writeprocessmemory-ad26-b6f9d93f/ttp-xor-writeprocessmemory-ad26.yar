rule TTP_XOR_WriteProcessMemory_ad26 {
  strings:
    $key_ad26 = { fa 54 [2] c8 76 [2] ce 43 [2] e0 43 [2] df 5f }

  condition:
    any of them
}