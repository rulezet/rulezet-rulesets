rule TTP_XOR_WriteProcessMemory_ecf8 {
  strings:
    $key_ecf8 = { bb 8a [2] 89 a8 [2] 8f 9d [2] a1 9d [2] 9e 81 }

  condition:
    any of them
}