rule TTP_XOR_WriteProcessMemory_001e {
  strings:
    $key_001e = { 57 6c [2] 65 4e [2] 63 7b [2] 4d 7b [2] 72 67 }

  condition:
    any of them
}