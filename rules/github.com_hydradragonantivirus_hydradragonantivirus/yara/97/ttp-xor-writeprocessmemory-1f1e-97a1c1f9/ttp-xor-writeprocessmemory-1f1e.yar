rule TTP_XOR_WriteProcessMemory_1f1e {
  strings:
    $key_1f1e = { 48 6c [2] 7a 4e [2] 7c 7b [2] 52 7b [2] 6d 67 }

  condition:
    any of them
}