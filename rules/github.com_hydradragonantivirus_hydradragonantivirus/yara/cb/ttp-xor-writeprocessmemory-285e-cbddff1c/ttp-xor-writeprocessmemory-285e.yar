rule TTP_XOR_WriteProcessMemory_285e {
  strings:
    $key_285e = { 7f 2c [2] 4d 0e [2] 4b 3b [2] 65 3b [2] 5a 27 }

  condition:
    any of them
}