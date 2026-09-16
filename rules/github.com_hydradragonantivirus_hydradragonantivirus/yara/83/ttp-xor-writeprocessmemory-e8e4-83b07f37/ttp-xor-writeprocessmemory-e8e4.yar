rule TTP_XOR_WriteProcessMemory_e8e4 {
  strings:
    $key_e8e4 = { bf 96 [2] 8d b4 [2] 8b 81 [2] a5 81 [2] 9a 9d }

  condition:
    any of them
}