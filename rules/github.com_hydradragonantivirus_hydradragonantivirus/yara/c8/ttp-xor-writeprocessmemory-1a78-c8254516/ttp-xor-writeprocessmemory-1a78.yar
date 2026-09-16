rule TTP_XOR_WriteProcessMemory_1a78 {
  strings:
    $key_1a78 = { 4d 0a [2] 7f 28 [2] 79 1d [2] 57 1d [2] 68 01 }

  condition:
    any of them
}