rule TTP_XOR_WriteProcessMemory_7f1e {
  strings:
    $key_7f1e = { 28 6c [2] 1a 4e [2] 1c 7b [2] 32 7b [2] 0d 67 }

  condition:
    any of them
}