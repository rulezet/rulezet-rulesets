rule TTP_XOR_WriteProcessMemory_5f3c {
  strings:
    $key_5f3c = { 08 4e [2] 3a 6c [2] 3c 59 [2] 12 59 [2] 2d 45 }

  condition:
    any of them
}