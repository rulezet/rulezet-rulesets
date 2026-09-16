rule TTP_XOR_WriteProcessMemory_400e {
  strings:
    $key_400e = { 17 7c [2] 25 5e [2] 23 6b [2] 0d 6b [2] 32 77 }

  condition:
    any of them
}