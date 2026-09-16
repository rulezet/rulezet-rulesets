rule TTP_XOR_WriteProcessMemory_e1c5 {
  strings:
    $key_e1c5 = { b6 b7 [2] 84 95 [2] 82 a0 [2] ac a0 [2] 93 bc }

  condition:
    any of them
}