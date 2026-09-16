rule TTP_XOR_WriteProcessMemory_43e6 {
  strings:
    $key_43e6 = { 14 94 [2] 26 b6 [2] 20 83 [2] 0e 83 [2] 31 9f }

  condition:
    any of them
}