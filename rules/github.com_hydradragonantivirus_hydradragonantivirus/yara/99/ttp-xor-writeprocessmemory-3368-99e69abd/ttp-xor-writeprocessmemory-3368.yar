rule TTP_XOR_WriteProcessMemory_3368 {
  strings:
    $key_3368 = { 64 1a [2] 56 38 [2] 50 0d [2] 7e 0d [2] 41 11 }

  condition:
    any of them
}