rule TTP_XOR_WriteProcessMemory_0e4c {
  strings:
    $key_0e4c = { 59 3e [2] 6b 1c [2] 6d 29 [2] 43 29 [2] 7c 35 }

  condition:
    any of them
}