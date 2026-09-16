rule TTP_XOR_WriteProcessMemory_e162 {
  strings:
    $key_e162 = { b6 10 [2] 84 32 [2] 82 07 [2] ac 07 [2] 93 1b }

  condition:
    any of them
}