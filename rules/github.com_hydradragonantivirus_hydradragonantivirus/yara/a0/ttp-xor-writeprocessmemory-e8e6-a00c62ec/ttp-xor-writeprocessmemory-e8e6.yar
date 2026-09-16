rule TTP_XOR_WriteProcessMemory_e8e6 {
  strings:
    $key_e8e6 = { bf 94 [2] 8d b6 [2] 8b 83 [2] a5 83 [2] 9a 9f }

  condition:
    any of them
}