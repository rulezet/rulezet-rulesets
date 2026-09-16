rule TTP_XOR_WriteProcessMemory_e65e {
  strings:
    $key_e65e = { b1 2c [2] 83 0e [2] 85 3b [2] ab 3b [2] 94 27 }

  condition:
    any of them
}