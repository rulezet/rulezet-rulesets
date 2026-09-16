rule TTP_XOR_WriteProcessMemory_370c {
  strings:
    $key_370c = { 60 7e [2] 52 5c [2] 54 69 [2] 7a 69 [2] 45 75 }

  condition:
    any of them
}