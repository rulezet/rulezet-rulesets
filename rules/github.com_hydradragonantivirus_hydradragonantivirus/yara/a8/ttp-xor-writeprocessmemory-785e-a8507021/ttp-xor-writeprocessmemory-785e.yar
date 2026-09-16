rule TTP_XOR_WriteProcessMemory_785e {
  strings:
    $key_785e = { 2f 2c [2] 1d 0e [2] 1b 3b [2] 35 3b [2] 0a 27 }

  condition:
    any of them
}