rule TTP_XOR_WriteProcessMemory_e15e {
  strings:
    $key_e15e = { b6 2c [2] 84 0e [2] 82 3b [2] ac 3b [2] 93 27 }

  condition:
    any of them
}