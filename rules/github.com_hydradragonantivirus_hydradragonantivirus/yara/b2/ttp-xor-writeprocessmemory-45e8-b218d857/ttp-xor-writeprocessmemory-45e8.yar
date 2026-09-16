rule TTP_XOR_WriteProcessMemory_45e8 {
  strings:
    $key_45e8 = { 12 9a [2] 20 b8 [2] 26 8d [2] 08 8d [2] 37 91 }

  condition:
    any of them
}