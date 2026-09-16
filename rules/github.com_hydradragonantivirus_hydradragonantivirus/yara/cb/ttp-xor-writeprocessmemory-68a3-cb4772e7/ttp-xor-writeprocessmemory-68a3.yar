rule TTP_XOR_WriteProcessMemory_68a3 {
  strings:
    $key_68a3 = { 3f d1 [2] 0d f3 [2] 0b c6 [2] 25 c6 [2] 1a da }

  condition:
    any of them
}