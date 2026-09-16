rule TTP_XOR_WriteProcessMemory_29f8 {
  strings:
    $key_29f8 = { 7e 8a [2] 4c a8 [2] 4a 9d [2] 64 9d [2] 5b 81 }

  condition:
    any of them
}