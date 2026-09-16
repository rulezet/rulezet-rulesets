rule TTP_XOR_WriteProcessMemory_6d5c {
  strings:
    $key_6d5c = { 3a 2e [2] 08 0c [2] 0e 39 [2] 20 39 [2] 1f 25 }

  condition:
    any of them
}