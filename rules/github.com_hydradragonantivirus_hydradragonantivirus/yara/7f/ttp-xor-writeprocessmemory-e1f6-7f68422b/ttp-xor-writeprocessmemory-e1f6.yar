rule TTP_XOR_WriteProcessMemory_e1f6 {
  strings:
    $key_e1f6 = { b6 84 [2] 84 a6 [2] 82 93 [2] ac 93 [2] 93 8f }

  condition:
    any of them
}