rule TTP_XOR_WriteProcessMemory_adf6 {
  strings:
    $key_adf6 = { fa 84 [2] c8 a6 [2] ce 93 [2] e0 93 [2] df 8f }

  condition:
    any of them
}