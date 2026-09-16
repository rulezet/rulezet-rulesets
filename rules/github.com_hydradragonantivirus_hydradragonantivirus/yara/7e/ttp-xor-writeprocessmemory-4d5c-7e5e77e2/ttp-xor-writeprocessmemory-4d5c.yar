rule TTP_XOR_WriteProcessMemory_4d5c {
  strings:
    $key_4d5c = { 1a 2e [2] 28 0c [2] 2e 39 [2] 00 39 [2] 3f 25 }

  condition:
    any of them
}