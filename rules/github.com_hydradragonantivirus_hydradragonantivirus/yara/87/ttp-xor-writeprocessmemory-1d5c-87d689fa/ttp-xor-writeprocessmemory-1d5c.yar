rule TTP_XOR_WriteProcessMemory_1d5c {
  strings:
    $key_1d5c = { 4a 2e [2] 78 0c [2] 7e 39 [2] 50 39 [2] 6f 25 }

  condition:
    any of them
}