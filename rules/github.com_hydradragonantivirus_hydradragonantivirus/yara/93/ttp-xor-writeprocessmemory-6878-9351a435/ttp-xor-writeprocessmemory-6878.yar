rule TTP_XOR_WriteProcessMemory_6878 {
  strings:
    $key_6878 = { 3f 0a [2] 0d 28 [2] 0b 1d [2] 25 1d [2] 1a 01 }

  condition:
    any of them
}