rule TTP_XOR_WriteProcessMemory_005e {
  strings:
    $key_005e = { 57 2c [2] 65 0e [2] 63 3b [2] 4d 3b [2] 72 27 }

  condition:
    any of them
}