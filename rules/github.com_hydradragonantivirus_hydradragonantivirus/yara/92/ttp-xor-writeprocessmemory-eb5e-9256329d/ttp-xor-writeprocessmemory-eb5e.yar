rule TTP_XOR_WriteProcessMemory_eb5e {
  strings:
    $key_eb5e = { bc 2c [2] 8e 0e [2] 88 3b [2] a6 3b [2] 99 27 }

  condition:
    any of them
}