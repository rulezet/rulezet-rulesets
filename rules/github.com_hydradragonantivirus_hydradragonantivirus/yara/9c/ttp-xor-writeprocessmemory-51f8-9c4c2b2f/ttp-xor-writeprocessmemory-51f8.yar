rule TTP_XOR_WriteProcessMemory_51f8 {
  strings:
    $key_51f8 = { 06 8a [2] 34 a8 [2] 32 9d [2] 1c 9d [2] 23 81 }

  condition:
    any of them
}