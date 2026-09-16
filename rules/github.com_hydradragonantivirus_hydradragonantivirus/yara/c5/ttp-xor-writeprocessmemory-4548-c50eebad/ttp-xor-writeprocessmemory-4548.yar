rule TTP_XOR_WriteProcessMemory_4548 {
  strings:
    $key_4548 = { 12 3a [2] 20 18 [2] 26 2d [2] 08 2d [2] 37 31 }

  condition:
    any of them
}