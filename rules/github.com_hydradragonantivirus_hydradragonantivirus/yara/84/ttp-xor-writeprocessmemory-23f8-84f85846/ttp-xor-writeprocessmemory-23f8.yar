rule TTP_XOR_WriteProcessMemory_23f8 {
  strings:
    $key_23f8 = { 74 8a [2] 46 a8 [2] 40 9d [2] 6e 9d [2] 51 81 }

  condition:
    any of them
}