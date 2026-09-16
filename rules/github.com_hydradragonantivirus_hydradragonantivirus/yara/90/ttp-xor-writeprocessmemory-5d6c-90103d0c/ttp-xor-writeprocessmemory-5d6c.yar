rule TTP_XOR_WriteProcessMemory_5d6c {
  strings:
    $key_5d6c = { 0a 1e [2] 38 3c [2] 3e 09 [2] 10 09 [2] 2f 15 }

  condition:
    any of them
}