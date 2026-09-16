rule TTP_XOR_WriteProcessMemory_ad56 {
  strings:
    $key_ad56 = { fa 24 [2] c8 06 [2] ce 33 [2] e0 33 [2] df 2f }

  condition:
    any of them
}