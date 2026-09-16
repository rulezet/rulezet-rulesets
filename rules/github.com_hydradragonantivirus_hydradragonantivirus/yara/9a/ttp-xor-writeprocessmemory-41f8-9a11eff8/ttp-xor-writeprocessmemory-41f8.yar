rule TTP_XOR_WriteProcessMemory_41f8 {
  strings:
    $key_41f8 = { 16 8a [2] 24 a8 [2] 22 9d [2] 0c 9d [2] 33 81 }

  condition:
    any of them
}