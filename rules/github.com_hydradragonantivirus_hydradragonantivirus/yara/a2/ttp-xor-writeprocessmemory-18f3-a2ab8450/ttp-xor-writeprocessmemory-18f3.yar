rule TTP_XOR_WriteProcessMemory_18f3 {
  strings:
    $key_18f3 = { 4f 81 [2] 7d a3 [2] 7b 96 [2] 55 96 [2] 6a 8a }

  condition:
    any of them
}