rule TTP_XOR_WriteProcessMemory_e17c {
  strings:
    $key_e17c = { b6 0e [2] 84 2c [2] 82 19 [2] ac 19 [2] 93 05 }

  condition:
    any of them
}