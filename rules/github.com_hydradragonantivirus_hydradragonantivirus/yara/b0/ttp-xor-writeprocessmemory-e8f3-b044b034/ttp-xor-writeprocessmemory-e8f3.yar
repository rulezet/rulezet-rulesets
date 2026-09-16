rule TTP_XOR_WriteProcessMemory_e8f3 {
  strings:
    $key_e8f3 = { bf 81 [2] 8d a3 [2] 8b 96 [2] a5 96 [2] 9a 8a }

  condition:
    any of them
}