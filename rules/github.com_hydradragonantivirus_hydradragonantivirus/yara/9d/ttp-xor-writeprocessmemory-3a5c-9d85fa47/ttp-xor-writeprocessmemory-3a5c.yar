rule TTP_XOR_WriteProcessMemory_3a5c {
  strings:
    $key_3a5c = { 6d 2e [2] 5f 0c [2] 59 39 [2] 77 39 [2] 48 25 }

  condition:
    any of them
}