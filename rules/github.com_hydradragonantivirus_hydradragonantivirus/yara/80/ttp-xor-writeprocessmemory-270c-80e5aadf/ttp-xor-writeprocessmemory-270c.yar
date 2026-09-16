rule TTP_XOR_WriteProcessMemory_270c {
  strings:
    $key_270c = { 70 7e [2] 42 5c [2] 44 69 [2] 6a 69 [2] 55 75 }

  condition:
    any of them
}