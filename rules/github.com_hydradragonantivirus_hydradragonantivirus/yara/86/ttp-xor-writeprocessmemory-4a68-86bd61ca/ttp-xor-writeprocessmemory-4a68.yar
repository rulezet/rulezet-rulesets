rule TTP_XOR_WriteProcessMemory_4a68 {
  strings:
    $key_4a68 = { 1d 1a [2] 2f 38 [2] 29 0d [2] 07 0d [2] 38 11 }

  condition:
    any of them
}