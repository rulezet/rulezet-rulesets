rule TTP_XOR_WriteProcessMemory_e9f3 {
  strings:
    $key_e9f3 = { be 81 [2] 8c a3 [2] 8a 96 [2] a4 96 [2] 9b 8a }

  condition:
    any of them
}