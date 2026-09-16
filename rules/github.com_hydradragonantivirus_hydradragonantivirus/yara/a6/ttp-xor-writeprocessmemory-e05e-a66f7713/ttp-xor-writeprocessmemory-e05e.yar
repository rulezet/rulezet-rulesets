rule TTP_XOR_WriteProcessMemory_e05e {
  strings:
    $key_e05e = { b7 2c [2] 85 0e [2] 83 3b [2] ad 3b [2] 92 27 }

  condition:
    any of them
}