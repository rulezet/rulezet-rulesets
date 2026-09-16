rule TTP_XOR_WriteProcessMemory_327c {
  strings:
    $key_327c = { 65 0e [2] 57 2c [2] 51 19 [2] 7f 19 [2] 40 05 }

  condition:
    any of them
}