rule TTP_XOR_WriteProcessMemory_0e6c {
  strings:
    $key_0e6c = { 59 1e [2] 6b 3c [2] 6d 09 [2] 43 09 [2] 7c 15 }

  condition:
    any of them
}