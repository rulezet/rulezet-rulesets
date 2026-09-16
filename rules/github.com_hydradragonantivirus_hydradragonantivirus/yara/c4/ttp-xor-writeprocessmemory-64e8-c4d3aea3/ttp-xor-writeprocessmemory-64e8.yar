rule TTP_XOR_WriteProcessMemory_64e8 {
  strings:
    $key_64e8 = { 33 9a [2] 01 b8 [2] 07 8d [2] 29 8d [2] 16 91 }

  condition:
    any of them
}