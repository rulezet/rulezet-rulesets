rule TTP_XOR_WriteProcessMemory_e25e {
  strings:
    $key_e25e = { b5 2c [2] 87 0e [2] 81 3b [2] af 3b [2] 90 27 }

  condition:
    any of them
}