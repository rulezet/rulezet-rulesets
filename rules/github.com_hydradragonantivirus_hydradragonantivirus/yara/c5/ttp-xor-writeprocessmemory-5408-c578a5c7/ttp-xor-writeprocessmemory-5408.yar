rule TTP_XOR_WriteProcessMemory_5408 {
  strings:
    $key_5408 = { 03 7a [2] 31 58 [2] 37 6d [2] 19 6d [2] 26 71 }

  condition:
    any of them
}