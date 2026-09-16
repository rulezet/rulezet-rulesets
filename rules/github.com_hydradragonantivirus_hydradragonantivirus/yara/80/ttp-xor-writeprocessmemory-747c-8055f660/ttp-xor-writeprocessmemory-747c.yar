rule TTP_XOR_WriteProcessMemory_747c {
  strings:
    $key_747c = { 23 0e [2] 11 2c [2] 17 19 [2] 39 19 [2] 06 05 }

  condition:
    any of them
}