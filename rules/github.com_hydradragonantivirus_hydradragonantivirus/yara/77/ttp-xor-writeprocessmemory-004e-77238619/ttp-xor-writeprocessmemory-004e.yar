rule TTP_XOR_WriteProcessMemory_004e {
  strings:
    $key_004e = { 57 3c [2] 65 1e [2] 63 2b [2] 4d 2b [2] 72 37 }

  condition:
    any of them
}