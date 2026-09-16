rule TTP_XOR_WriteProcessMemory_5a1e {
  strings:
    $key_5a1e = { 0d 6c [2] 3f 4e [2] 39 7b [2] 17 7b [2] 28 67 }

  condition:
    any of them
}