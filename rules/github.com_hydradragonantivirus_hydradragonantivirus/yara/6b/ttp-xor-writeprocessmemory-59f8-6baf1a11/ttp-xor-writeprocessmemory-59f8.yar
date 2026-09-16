rule TTP_XOR_WriteProcessMemory_59f8 {
  strings:
    $key_59f8 = { 0e 8a [2] 3c a8 [2] 3a 9d [2] 14 9d [2] 2b 81 }

  condition:
    any of them
}