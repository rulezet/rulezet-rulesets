rule TTP_XOR_WriteProcessMemory_21f8 {
  strings:
    $key_21f8 = { 76 8a [2] 44 a8 [2] 42 9d [2] 6c 9d [2] 53 81 }

  condition:
    any of them
}