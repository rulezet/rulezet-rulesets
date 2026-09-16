rule TTP_XOR_WriteProcessMemory_5a68 {
  strings:
    $key_5a68 = { 0d 1a [2] 3f 38 [2] 39 0d [2] 17 0d [2] 28 11 }

  condition:
    any of them
}