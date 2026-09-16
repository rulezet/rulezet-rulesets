rule TTP_XOR_WriteProcessMemory_3a6c {
  strings:
    $key_3a6c = { 6d 1e [2] 5f 3c [2] 59 09 [2] 77 09 [2] 48 15 }

  condition:
    any of them
}