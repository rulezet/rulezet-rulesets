rule TTP_XOR_WriteProcessMemory_634c {
  strings:
    $key_634c = { 34 3e [2] 06 1c [2] 00 29 [2] 2e 29 [2] 11 35 }

  condition:
    any of them
}