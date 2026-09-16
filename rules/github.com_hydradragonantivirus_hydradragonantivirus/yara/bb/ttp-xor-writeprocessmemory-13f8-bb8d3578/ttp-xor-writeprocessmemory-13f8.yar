rule TTP_XOR_WriteProcessMemory_13f8 {
  strings:
    $key_13f8 = { 44 8a [2] 76 a8 [2] 70 9d [2] 5e 9d [2] 61 81 }

  condition:
    any of them
}