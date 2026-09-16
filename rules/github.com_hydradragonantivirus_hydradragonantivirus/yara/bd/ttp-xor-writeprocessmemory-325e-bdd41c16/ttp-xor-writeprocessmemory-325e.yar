rule TTP_XOR_WriteProcessMemory_325e {
  strings:
    $key_325e = { 65 2c [2] 57 0e [2] 51 3b [2] 7f 3b [2] 40 27 }

  condition:
    any of them
}