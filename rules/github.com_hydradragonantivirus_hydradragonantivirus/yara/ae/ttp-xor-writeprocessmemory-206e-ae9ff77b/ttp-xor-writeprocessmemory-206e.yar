rule TTP_XOR_WriteProcessMemory_206e {
  strings:
    $key_206e = { 77 1c [2] 45 3e [2] 43 0b [2] 6d 0b [2] 52 17 }

  condition:
    any of them
}