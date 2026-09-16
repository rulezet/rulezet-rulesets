rule TTP_XOR_WriteProcessMemory_09f8 {
  strings:
    $key_09f8 = { 5e 8a [2] 6c a8 [2] 6a 9d [2] 44 9d [2] 7b 81 }

  condition:
    any of them
}