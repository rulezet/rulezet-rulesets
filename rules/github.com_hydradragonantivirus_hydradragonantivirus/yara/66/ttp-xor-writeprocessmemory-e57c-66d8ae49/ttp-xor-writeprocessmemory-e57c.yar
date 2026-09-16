rule TTP_XOR_WriteProcessMemory_e57c {
  strings:
    $key_e57c = { b2 0e [2] 80 2c [2] 86 19 [2] a8 19 [2] 97 05 }

  condition:
    any of them
}