rule TTP_XOR_WriteProcessMemory_68e8 {
  strings:
    $key_68e8 = { 3f 9a [2] 0d b8 [2] 0b 8d [2] 25 8d [2] 1a 91 }

  condition:
    any of them
}