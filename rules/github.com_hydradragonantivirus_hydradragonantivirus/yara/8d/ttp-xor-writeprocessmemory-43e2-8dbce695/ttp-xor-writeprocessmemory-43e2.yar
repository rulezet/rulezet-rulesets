rule TTP_XOR_WriteProcessMemory_43e2 {
  strings:
    $key_43e2 = { 14 90 [2] 26 b2 [2] 20 87 [2] 0e 87 [2] 31 9b }

  condition:
    any of them
}