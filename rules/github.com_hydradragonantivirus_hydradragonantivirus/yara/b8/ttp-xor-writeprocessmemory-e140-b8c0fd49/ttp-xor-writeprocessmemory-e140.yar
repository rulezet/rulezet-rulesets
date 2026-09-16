rule TTP_XOR_WriteProcessMemory_e140 {
  strings:
    $key_e140 = { b6 32 [2] 84 10 [2] 82 25 [2] ac 25 [2] 93 39 }

  condition:
    any of them
}