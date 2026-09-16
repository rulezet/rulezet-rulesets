rule TTP_XOR_WriteProcessMemory_68e1 {
  strings:
    $key_68e1 = { 3f 93 [2] 0d b1 [2] 0b 84 [2] 25 84 [2] 1a 98 }

  condition:
    any of them
}