rule TTP_XOR_WriteProcessMemory_0b6c {
  strings:
    $key_0b6c = { 5c 1e [2] 6e 3c [2] 68 09 [2] 46 09 [2] 79 15 }

  condition:
    any of them
}