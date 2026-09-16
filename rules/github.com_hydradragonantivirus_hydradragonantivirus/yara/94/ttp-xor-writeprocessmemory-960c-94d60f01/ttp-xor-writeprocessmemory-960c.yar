rule TTP_XOR_WriteProcessMemory_960c {
  strings:
    $key_960c = { c1 7e [2] f3 5c [2] f5 69 [2] db 69 [2] e4 75 }

  condition:
    any of them
}