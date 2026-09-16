rule TTP_XOR_WriteProcessMemory_491c {
  strings:
    $key_491c = { 1e 6e [2] 2c 4c [2] 2a 79 [2] 04 79 [2] 3b 65 }

  condition:
    any of them
}