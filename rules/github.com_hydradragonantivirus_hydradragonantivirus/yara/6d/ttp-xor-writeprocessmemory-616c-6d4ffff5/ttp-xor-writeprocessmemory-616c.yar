rule TTP_XOR_WriteProcessMemory_616c {
  strings:
    $key_616c = { 36 1e [2] 04 3c [2] 02 09 [2] 2c 09 [2] 13 15 }

  condition:
    any of them
}