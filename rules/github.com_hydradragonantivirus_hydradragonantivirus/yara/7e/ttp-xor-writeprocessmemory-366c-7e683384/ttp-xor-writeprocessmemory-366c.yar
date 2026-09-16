rule TTP_XOR_WriteProcessMemory_366c {
  strings:
    $key_366c = { 61 1e [2] 53 3c [2] 55 09 [2] 7b 09 [2] 44 15 }

  condition:
    any of them
}