rule TTP_XOR_WriteProcessMemory_6f1e {
  strings:
    $key_6f1e = { 38 6c [2] 0a 4e [2] 0c 7b [2] 22 7b [2] 1d 67 }

  condition:
    any of them
}