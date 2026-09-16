rule TTP_XOR_WriteProcessMemory_fff8 {
  strings:
    $key_fff8 = { a8 8a [2] 9a a8 [2] 9c 9d [2] b2 9d [2] 8d 81 }

  condition:
    any of them
}