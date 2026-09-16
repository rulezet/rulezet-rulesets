rule TTP_XOR_WriteProcessMemory_e1f3 {
  strings:
    $key_e1f3 = { b6 81 [2] 84 a3 [2] 82 96 [2] ac 96 [2] 93 8a }

  condition:
    any of them
}