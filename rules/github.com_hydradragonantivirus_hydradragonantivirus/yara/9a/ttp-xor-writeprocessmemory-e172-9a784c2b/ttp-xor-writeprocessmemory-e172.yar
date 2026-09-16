rule TTP_XOR_WriteProcessMemory_e172 {
  strings:
    $key_e172 = { b6 00 [2] 84 22 [2] 82 17 [2] ac 17 [2] 93 0b }

  condition:
    any of them
}