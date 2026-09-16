rule TTP_XOR_WriteProcessMemory_470c {
  strings:
    $key_470c = { 10 7e [2] 22 5c [2] 24 69 [2] 0a 69 [2] 35 75 }

  condition:
    any of them
}