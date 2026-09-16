rule TTP_XOR_WriteProcessMemory_3f1e {
  strings:
    $key_3f1e = { 68 6c [2] 5a 4e [2] 5c 7b [2] 72 7b [2] 4d 67 }

  condition:
    any of them
}