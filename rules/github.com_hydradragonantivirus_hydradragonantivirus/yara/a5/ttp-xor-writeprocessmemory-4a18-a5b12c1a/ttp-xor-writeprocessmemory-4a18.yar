rule TTP_XOR_WriteProcessMemory_4a18 {
  strings:
    $key_4a18 = { 1d 6a [2] 2f 48 [2] 29 7d [2] 07 7d [2] 38 61 }

  condition:
    any of them
}