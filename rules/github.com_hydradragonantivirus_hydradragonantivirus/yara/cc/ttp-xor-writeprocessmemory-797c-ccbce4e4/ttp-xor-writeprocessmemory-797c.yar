rule TTP_XOR_WriteProcessMemory_797c {
  strings:
    $key_797c = { 2e 0e [2] 1c 2c [2] 1a 19 [2] 34 19 [2] 0b 05 }

  condition:
    any of them
}