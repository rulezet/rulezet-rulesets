rule TTP_XOR_WriteProcessMemory_5208 {
  strings:
    $key_5208 = { 05 7a [2] 37 58 [2] 31 6d [2] 1f 6d [2] 20 71 }

  condition:
    any of them
}