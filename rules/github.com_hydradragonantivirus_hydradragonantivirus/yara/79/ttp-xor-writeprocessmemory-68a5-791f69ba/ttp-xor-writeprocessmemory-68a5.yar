rule TTP_XOR_WriteProcessMemory_68a5 {
  strings:
    $key_68a5 = { 3f d7 [2] 0d f5 [2] 0b c0 [2] 25 c0 [2] 1a dc }

  condition:
    any of them
}