rule TTP_XOR_WriteProcessMemory_180e {
  strings:
    $key_180e = { 4f 7c [2] 7d 5e [2] 7b 6b [2] 55 6b [2] 6a 77 }

  condition:
    any of them
}