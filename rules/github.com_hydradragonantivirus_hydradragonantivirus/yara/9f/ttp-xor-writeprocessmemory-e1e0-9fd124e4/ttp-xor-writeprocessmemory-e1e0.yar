rule TTP_XOR_WriteProcessMemory_e1e0 {
  strings:
    $key_e1e0 = { b6 92 [2] 84 b0 [2] 82 85 [2] ac 85 [2] 93 99 }

  condition:
    any of them
}