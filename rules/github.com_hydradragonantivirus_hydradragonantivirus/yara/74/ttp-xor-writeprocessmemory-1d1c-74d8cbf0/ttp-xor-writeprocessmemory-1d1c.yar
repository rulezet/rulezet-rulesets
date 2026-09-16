rule TTP_XOR_WriteProcessMemory_1d1c {
  strings:
    $key_1d1c = { 4a 6e [2] 78 4c [2] 7e 79 [2] 50 79 [2] 6f 65 }

  condition:
    any of them
}