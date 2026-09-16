rule TTP_XOR_WriteProcessMemory_1c4c {
  strings:
    $key_1c4c = { 4b 3e [2] 79 1c [2] 7f 29 [2] 51 29 [2] 6e 35 }

  condition:
    any of them
}