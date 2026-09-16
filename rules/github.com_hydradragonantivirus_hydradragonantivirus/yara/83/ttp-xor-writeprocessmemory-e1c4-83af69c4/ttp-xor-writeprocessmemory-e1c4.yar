rule TTP_XOR_WriteProcessMemory_e1c4 {
  strings:
    $key_e1c4 = { b6 b6 [2] 84 94 [2] 82 a1 [2] ac a1 [2] 93 bd }

  condition:
    any of them
}