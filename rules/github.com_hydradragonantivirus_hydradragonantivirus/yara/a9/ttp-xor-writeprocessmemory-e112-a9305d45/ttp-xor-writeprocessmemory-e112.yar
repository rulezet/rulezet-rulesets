rule TTP_XOR_WriteProcessMemory_e112 {
  strings:
    $key_e112 = { b6 60 [2] 84 42 [2] 82 77 [2] ac 77 [2] 93 6b }

  condition:
    any of them
}