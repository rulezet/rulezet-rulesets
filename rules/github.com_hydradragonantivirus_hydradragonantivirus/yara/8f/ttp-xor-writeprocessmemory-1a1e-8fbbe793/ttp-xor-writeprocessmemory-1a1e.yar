rule TTP_XOR_WriteProcessMemory_1a1e {
  strings:
    $key_1a1e = { 4d 6c [2] 7f 4e [2] 79 7b [2] 57 7b [2] 68 67 }

  condition:
    any of them
}