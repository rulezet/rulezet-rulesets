rule TTP_XOR_WriteProcessMemory_5fe8 {
  strings:
    $key_5fe8 = { 08 9a [2] 3a b8 [2] 3c 8d [2] 12 8d [2] 2d 91 }

  condition:
    any of them
}