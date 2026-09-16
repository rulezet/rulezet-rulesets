rule TTP_XOR_WriteProcessMemory_045e {
  strings:
    $key_045e = { 53 2c [2] 61 0e [2] 67 3b [2] 49 3b [2] 76 27 }

  condition:
    any of them
}