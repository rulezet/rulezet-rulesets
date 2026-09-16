rule TTP_XOR_WriteProcessMemory_68f8 {
  strings:
    $key_68f8 = { 3f 8a [2] 0d a8 [2] 0b 9d [2] 25 9d [2] 1a 81 }

  condition:
    any of them
}