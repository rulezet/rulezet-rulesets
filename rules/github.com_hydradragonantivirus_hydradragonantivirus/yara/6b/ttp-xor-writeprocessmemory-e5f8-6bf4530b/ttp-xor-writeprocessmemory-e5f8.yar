rule TTP_XOR_WriteProcessMemory_e5f8 {
  strings:
    $key_e5f8 = { b2 8a [2] 80 a8 [2] 86 9d [2] a8 9d [2] 97 81 }

  condition:
    any of them
}