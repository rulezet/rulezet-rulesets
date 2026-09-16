rule TTP_XOR_WriteProcessMemory_e9f2 {
  strings:
    $key_e9f2 = { be 80 [2] 8c a2 [2] 8a 97 [2] a4 97 [2] 9b 8b }

  condition:
    any of them
}