rule TTP_XOR_WriteProcessMemory_073d {
  strings:
    $key_073d = { 50 4f [2] 62 6d [2] 64 58 [2] 4a 58 [2] 75 44 }

  condition:
    any of them
}