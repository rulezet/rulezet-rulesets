rule TTP_XOR_WriteProcessMemory_37e8 {
  strings:
    $key_37e8 = { 60 9a [2] 52 b8 [2] 54 8d [2] 7a 8d [2] 45 91 }

  condition:
    any of them
}