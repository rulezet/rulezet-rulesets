rule TTP_XOR_WriteProcessMemory_403d {
  strings:
    $key_403d = { 17 4f [2] 25 6d [2] 23 58 [2] 0d 58 [2] 32 44 }

  condition:
    any of them
}