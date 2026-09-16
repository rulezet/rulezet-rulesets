rule TTP_XOR_WriteProcessMemory_32f8 {
  strings:
    $key_32f8 = { 65 8a [2] 57 a8 [2] 51 9d [2] 7f 9d [2] 40 81 }

  condition:
    any of them
}