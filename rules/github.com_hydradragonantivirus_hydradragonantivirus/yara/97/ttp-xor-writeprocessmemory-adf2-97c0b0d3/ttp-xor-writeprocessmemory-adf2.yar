rule TTP_XOR_WriteProcessMemory_adf2 {
  strings:
    $key_adf2 = { fa 80 [2] c8 a2 [2] ce 97 [2] e0 97 [2] df 8b }

  condition:
    any of them
}