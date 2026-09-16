rule TTP_XOR_WriteProcessMemory_37f8 {
  strings:
    $key_37f8 = { 60 8a [2] 52 a8 [2] 54 9d [2] 7a 9d [2] 45 81 }

  condition:
    any of them
}