rule TTP_XOR_WriteProcessMemory_49f8 {
  strings:
    $key_49f8 = { 1e 8a [2] 2c a8 [2] 2a 9d [2] 04 9d [2] 3b 81 }

  condition:
    any of them
}