rule TTP_XOR_WriteProcessMemory_08f8 {
  strings:
    $key_08f8 = { 5f 8a [2] 6d a8 [2] 6b 9d [2] 45 9d [2] 7a 81 }

  condition:
    any of them
}