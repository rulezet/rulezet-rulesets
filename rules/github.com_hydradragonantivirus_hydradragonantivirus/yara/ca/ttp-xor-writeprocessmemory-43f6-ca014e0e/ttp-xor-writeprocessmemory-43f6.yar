rule TTP_XOR_WriteProcessMemory_43f6 {
  strings:
    $key_43f6 = { 14 84 [2] 26 a6 [2] 20 93 [2] 0e 93 [2] 31 8f }

  condition:
    any of them
}