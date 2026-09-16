rule TTP_XOR_WriteProcessMemory_457c {
  strings:
    $key_457c = { 12 0e [2] 20 2c [2] 26 19 [2] 08 19 [2] 37 05 }

  condition:
    any of them
}