rule TTP_XOR_WriteProcessMemory_4768 {
  strings:
    $key_4768 = { 10 1a [2] 22 38 [2] 24 0d [2] 0a 0d [2] 35 11 }

  condition:
    any of them
}