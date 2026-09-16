rule TTP_XOR_WriteProcessMemory_154e {
  strings:
    $key_154e = { 42 3c [2] 70 1e [2] 76 2b [2] 58 2b [2] 67 37 }

  condition:
    any of them
}