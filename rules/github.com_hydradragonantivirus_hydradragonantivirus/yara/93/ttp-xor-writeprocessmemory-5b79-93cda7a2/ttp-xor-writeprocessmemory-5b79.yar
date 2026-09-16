rule TTP_XOR_WriteProcessMemory_5b79 {
  strings:
    $key_5b79 = { 0c 0b [2] 3e 29 [2] 38 1c [2] 16 1c [2] 29 00 }

  condition:
    any of them
}