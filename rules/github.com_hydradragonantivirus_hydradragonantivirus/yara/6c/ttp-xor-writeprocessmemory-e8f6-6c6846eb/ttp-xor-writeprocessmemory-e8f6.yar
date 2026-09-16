rule TTP_XOR_WriteProcessMemory_e8f6 {
  strings:
    $key_e8f6 = { bf 84 [2] 8d a6 [2] 8b 93 [2] a5 93 [2] 9a 8f }

  condition:
    any of them
}