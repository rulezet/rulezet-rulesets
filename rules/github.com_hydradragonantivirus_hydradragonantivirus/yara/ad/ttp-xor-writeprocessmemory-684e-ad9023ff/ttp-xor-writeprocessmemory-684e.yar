rule TTP_XOR_WriteProcessMemory_684e {
  strings:
    $key_684e = { 3f 3c [2] 0d 1e [2] 0b 2b [2] 25 2b [2] 1a 37 }

  condition:
    any of them
}