rule TTP_XOR_WriteProcessMemory_7a68 {
  strings:
    $key_7a68 = { 2d 1a [2] 1f 38 [2] 19 0d [2] 37 0d [2] 08 11 }

  condition:
    any of them
}