rule TTP_XOR_WriteProcessMemory_e136 {
  strings:
    $key_e136 = { b6 44 [2] 84 66 [2] 82 53 [2] ac 53 [2] 93 4f }

  condition:
    any of them
}