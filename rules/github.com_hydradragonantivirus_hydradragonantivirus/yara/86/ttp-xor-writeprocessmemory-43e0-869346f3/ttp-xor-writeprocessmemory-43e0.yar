rule TTP_XOR_WriteProcessMemory_43e0 {
  strings:
    $key_43e0 = { 14 92 [2] 26 b0 [2] 20 85 [2] 0e 85 [2] 31 99 }

  condition:
    any of them
}