rule TTP_XOR_WriteProcessMemory_6248 {
  strings:
    $key_6248 = { 35 3a [2] 07 18 [2] 01 2d [2] 2f 2d [2] 10 31 }

  condition:
    any of them
}