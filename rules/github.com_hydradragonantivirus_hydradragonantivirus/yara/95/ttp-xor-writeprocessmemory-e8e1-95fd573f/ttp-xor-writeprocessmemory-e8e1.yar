rule TTP_XOR_WriteProcessMemory_e8e1 {
  strings:
    $key_e8e1 = { bf 93 [2] 8d b1 [2] 8b 84 [2] a5 84 [2] 9a 98 }

  condition:
    any of them
}