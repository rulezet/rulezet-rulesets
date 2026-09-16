rule TTP_XOR_WriteProcessMemory_0b1c {
  strings:
    $key_0b1c = { 5c 6e [2] 6e 4c [2] 68 79 [2] 46 79 [2] 79 65 }

  condition:
    any of them
}