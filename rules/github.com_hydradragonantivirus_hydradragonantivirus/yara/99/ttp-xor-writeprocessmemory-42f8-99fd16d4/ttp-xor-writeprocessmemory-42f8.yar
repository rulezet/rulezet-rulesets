rule TTP_XOR_WriteProcessMemory_42f8 {
  strings:
    $key_42f8 = { 15 8a [2] 27 a8 [2] 21 9d [2] 0f 9d [2] 30 81 }

  condition:
    any of them
}