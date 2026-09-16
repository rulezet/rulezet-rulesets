rule TTP_XOR_WriteProcessMemory_545e {
  strings:
    $key_545e = { 03 2c [2] 31 0e [2] 37 3b [2] 19 3b [2] 26 27 }

  condition:
    any of them
}