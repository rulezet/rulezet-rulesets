rule TTP_XOR_WriteProcessMemory_404c {
  strings:
    $key_404c = { 17 3e [2] 25 1c [2] 23 29 [2] 0d 29 [2] 32 35 }

  condition:
    any of them
}