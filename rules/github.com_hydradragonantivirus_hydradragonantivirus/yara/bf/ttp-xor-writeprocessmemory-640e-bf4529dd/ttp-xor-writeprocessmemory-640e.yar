rule TTP_XOR_WriteProcessMemory_640e {
  strings:
    $key_640e = { 33 7c [2] 01 5e [2] 07 6b [2] 29 6b [2] 16 77 }

  condition:
    any of them
}