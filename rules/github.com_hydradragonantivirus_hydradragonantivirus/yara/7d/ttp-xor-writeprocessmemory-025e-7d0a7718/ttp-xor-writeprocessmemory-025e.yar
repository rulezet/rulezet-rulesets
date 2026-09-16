rule TTP_XOR_WriteProcessMemory_025e {
  strings:
    $key_025e = { 55 2c [2] 67 0e [2] 61 3b [2] 4f 3b [2] 70 27 }

  condition:
    any of them
}