rule TTP_XOR_WriteProcessMemory_f3f8 {
  strings:
    $key_f3f8 = { a4 8a [2] 96 a8 [2] 90 9d [2] be 9d [2] 81 81 }

  condition:
    any of them
}