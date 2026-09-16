rule TTP_XOR_WriteProcessMemory_1b79 {
  strings:
    $key_1b79 = { 4c 0b [2] 7e 29 [2] 78 1c [2] 56 1c [2] 69 00 }

  condition:
    any of them
}