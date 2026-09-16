rule TTP_XOR_WriteProcessMemory_153e {
  strings:
    $key_153e = { 42 4c [2] 70 6e [2] 76 5b [2] 58 5b [2] 67 47 }

  condition:
    any of them
}