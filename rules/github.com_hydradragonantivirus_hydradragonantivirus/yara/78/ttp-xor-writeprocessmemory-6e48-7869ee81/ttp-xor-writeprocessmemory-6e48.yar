rule TTP_XOR_WriteProcessMemory_6e48 {
  strings:
    $key_6e48 = { 39 3a [2] 0b 18 [2] 0d 2d [2] 23 2d [2] 1c 31 }

  condition:
    any of them
}