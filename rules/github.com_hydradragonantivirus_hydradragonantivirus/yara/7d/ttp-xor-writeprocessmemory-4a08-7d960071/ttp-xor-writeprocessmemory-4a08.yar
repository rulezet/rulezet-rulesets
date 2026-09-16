rule TTP_XOR_WriteProcessMemory_4a08 {
  strings:
    $key_4a08 = { 1d 7a [2] 2f 58 [2] 29 6d [2] 07 6d [2] 38 71 }

  condition:
    any of them
}