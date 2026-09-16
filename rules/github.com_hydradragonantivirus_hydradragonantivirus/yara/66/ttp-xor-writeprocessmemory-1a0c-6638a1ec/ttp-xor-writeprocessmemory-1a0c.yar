rule TTP_XOR_WriteProcessMemory_1a0c {
  strings:
    $key_1a0c = { 4d 7e [2] 7f 5c [2] 79 69 [2] 57 69 [2] 68 75 }

  condition:
    any of them
}