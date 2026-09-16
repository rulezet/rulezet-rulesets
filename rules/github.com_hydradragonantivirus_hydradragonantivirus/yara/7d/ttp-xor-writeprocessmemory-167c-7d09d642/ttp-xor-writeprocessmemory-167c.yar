rule TTP_XOR_WriteProcessMemory_167c {
  strings:
    $key_167c = { 41 0e [2] 73 2c [2] 75 19 [2] 5b 19 [2] 64 05 }

  condition:
    any of them
}