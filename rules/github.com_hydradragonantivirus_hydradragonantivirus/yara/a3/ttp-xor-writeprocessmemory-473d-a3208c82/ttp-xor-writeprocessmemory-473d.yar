rule TTP_XOR_WriteProcessMemory_473d {
  strings:
    $key_473d = { 10 4f [2] 22 6d [2] 24 58 [2] 0a 58 [2] 35 44 }

  condition:
    any of them
}