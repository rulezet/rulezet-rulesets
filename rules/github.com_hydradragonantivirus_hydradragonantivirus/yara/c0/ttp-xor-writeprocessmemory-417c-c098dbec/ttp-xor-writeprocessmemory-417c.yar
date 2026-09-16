rule TTP_XOR_WriteProcessMemory_417c {
  strings:
    $key_417c = { 16 0e [2] 24 2c [2] 22 19 [2] 0c 19 [2] 33 05 }

  condition:
    any of them
}