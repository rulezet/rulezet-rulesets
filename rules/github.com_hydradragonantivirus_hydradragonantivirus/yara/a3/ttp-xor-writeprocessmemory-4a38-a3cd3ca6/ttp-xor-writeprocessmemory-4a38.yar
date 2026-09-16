rule TTP_XOR_WriteProcessMemory_4a38 {
  strings:
    $key_4a38 = { 1d 4a [2] 2f 68 [2] 29 5d [2] 07 5d [2] 38 41 }

  condition:
    any of them
}