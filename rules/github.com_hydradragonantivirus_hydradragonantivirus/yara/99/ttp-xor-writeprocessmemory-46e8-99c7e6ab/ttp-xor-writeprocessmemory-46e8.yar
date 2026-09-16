rule TTP_XOR_WriteProcessMemory_46e8 {
  strings:
    $key_46e8 = { 11 9a [2] 23 b8 [2] 25 8d [2] 0b 8d [2] 34 91 }

  condition:
    any of them
}