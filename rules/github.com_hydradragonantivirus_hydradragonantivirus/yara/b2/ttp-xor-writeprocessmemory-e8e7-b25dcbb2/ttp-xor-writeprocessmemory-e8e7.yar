rule TTP_XOR_WriteProcessMemory_e8e7 {
  strings:
    $key_e8e7 = { bf 95 [2] 8d b7 [2] 8b 82 [2] a5 82 [2] 9a 9e }

  condition:
    any of them
}