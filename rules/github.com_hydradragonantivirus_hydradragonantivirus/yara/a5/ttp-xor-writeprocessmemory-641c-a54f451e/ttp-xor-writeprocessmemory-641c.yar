rule TTP_XOR_WriteProcessMemory_641c {
  strings:
    $key_641c = { 33 6e [2] 01 4c [2] 07 79 [2] 29 79 [2] 16 65 }

  condition:
    any of them
}