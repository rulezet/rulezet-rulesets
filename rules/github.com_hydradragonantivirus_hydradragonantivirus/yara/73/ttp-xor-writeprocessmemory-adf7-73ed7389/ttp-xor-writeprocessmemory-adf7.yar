rule TTP_XOR_WriteProcessMemory_adf7 {
  strings:
    $key_adf7 = { fa 85 [2] c8 a7 [2] ce 92 [2] e0 92 [2] df 8e }

  condition:
    any of them
}