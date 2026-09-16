rule TTP_XOR_WriteProcessMemory_743c {
  strings:
    $key_743c = { 23 4e [2] 11 6c [2] 17 59 [2] 39 59 [2] 06 45 }

  condition:
    any of them
}