rule TTP_XOR_WriteProcessMemory_35f3 {
  strings:
    $key_35f3 = { 62 81 [2] 50 a3 [2] 56 96 [2] 78 96 [2] 47 8a }

  condition:
    any of them
}