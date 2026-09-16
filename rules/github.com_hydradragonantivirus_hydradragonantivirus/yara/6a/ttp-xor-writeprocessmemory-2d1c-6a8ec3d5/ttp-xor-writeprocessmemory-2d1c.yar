rule TTP_XOR_WriteProcessMemory_2d1c {
  strings:
    $key_2d1c = { 7a 6e [2] 48 4c [2] 4e 79 [2] 60 79 [2] 5f 65 }

  condition:
    any of them
}