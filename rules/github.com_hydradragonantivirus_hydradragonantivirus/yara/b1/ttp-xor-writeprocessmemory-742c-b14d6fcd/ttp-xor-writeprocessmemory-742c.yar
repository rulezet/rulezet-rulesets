rule TTP_XOR_WriteProcessMemory_742c {
  strings:
    $key_742c = { 23 5e [2] 11 7c [2] 17 49 [2] 39 49 [2] 06 55 }

  condition:
    any of them
}