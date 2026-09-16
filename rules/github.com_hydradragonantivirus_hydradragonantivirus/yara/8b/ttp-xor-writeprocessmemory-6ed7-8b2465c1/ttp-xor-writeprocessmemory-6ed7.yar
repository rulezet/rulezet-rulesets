rule TTP_XOR_WriteProcessMemory_6ed7 {
  strings:
    $key_6ed7 = { 39 a5 [2] 0b 87 [2] 0d b2 [2] 23 b2 [2] 1c ae }

  condition:
    any of them
}