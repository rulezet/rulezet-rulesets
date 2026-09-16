rule TTP_XOR_WriteProcessMemory_1d6c {
  strings:
    $key_1d6c = { 4a 1e [2] 78 3c [2] 7e 09 [2] 50 09 [2] 6f 15 }

  condition:
    any of them
}