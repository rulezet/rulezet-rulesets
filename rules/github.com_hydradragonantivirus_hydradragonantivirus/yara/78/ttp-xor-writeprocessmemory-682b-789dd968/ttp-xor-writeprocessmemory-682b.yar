rule TTP_XOR_WriteProcessMemory_682b {
  strings:
    $key_682b = { 3f 59 [2] 0d 7b [2] 0b 4e [2] 25 4e [2] 1a 52 }

  condition:
    any of them
}