rule TTP_XOR_WriteProcessMemory_484c {
  strings:
    $key_484c = { 1f 3e [2] 2d 1c [2] 2b 29 [2] 05 29 [2] 3a 35 }

  condition:
    any of them
}