rule TTP_XOR_WriteProcessMemory_68a2 {
  strings:
    $key_68a2 = { 3f d0 [2] 0d f2 [2] 0b c7 [2] 25 c7 [2] 1a db }

  condition:
    any of them
}