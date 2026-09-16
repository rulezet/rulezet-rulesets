rule TTP_XOR_WriteProcessMemory_962c {
  strings:
    $key_962c = { c1 5e [2] f3 7c [2] f5 49 [2] db 49 [2] e4 55 }

  condition:
    any of them
}