rule TTP_XOR_WriteProcessMemory_e1f0 {
  strings:
    $key_e1f0 = { b6 82 [2] 84 a0 [2] 82 95 [2] ac 95 [2] 93 89 }

  condition:
    any of them
}