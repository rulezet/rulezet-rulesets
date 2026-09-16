rule TTP_XOR_WriteProcessMemory_3a1c {
  strings:
    $key_3a1c = { 6d 6e [2] 5f 4c [2] 59 79 [2] 77 79 [2] 48 65 }

  condition:
    any of them
}