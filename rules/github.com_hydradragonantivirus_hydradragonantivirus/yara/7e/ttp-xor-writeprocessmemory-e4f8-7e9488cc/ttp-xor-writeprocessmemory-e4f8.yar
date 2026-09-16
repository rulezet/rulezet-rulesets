rule TTP_XOR_WriteProcessMemory_e4f8 {
  strings:
    $key_e4f8 = { b3 8a [2] 81 a8 [2] 87 9d [2] a9 9d [2] 96 81 }

  condition:
    any of them
}