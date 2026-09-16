rule TTP_XOR_WriteProcessMemory_3a2e {
  strings:
    $key_3a2e = { 6d 5c [2] 5f 7e [2] 59 4b [2] 77 4b [2] 48 57 }

  condition:
    any of them
}