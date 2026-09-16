rule TTP_XOR_WriteProcessMemory_1a38 {
  strings:
    $key_1a38 = { 4d 4a [2] 7f 68 [2] 79 5d [2] 57 5d [2] 68 41 }

  condition:
    any of them
}