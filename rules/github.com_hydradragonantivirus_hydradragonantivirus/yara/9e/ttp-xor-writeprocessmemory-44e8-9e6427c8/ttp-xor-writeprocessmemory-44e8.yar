rule TTP_XOR_WriteProcessMemory_44e8 {
  strings:
    $key_44e8 = { 13 9a [2] 21 b8 [2] 27 8d [2] 09 8d [2] 36 91 }

  condition:
    any of them
}