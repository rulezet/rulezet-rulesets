rule TTP_XOR_WriteProcessMemory_462c {
  strings:
    $key_462c = { 11 5e [2] 23 7c [2] 25 49 [2] 0b 49 [2] 34 55 }

  condition:
    any of them
}