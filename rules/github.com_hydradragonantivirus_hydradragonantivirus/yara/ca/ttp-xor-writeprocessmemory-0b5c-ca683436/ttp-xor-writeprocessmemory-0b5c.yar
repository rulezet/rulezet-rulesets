rule TTP_XOR_WriteProcessMemory_0b5c {
  strings:
    $key_0b5c = { 5c 2e [2] 6e 0c [2] 68 39 [2] 46 39 [2] 79 25 }

  condition:
    any of them
}