rule TTP_XOR_WriteProcessMemory_1f68 {
  strings:
    $key_1f68 = { 48 1a [2] 7a 38 [2] 7c 0d [2] 52 0d [2] 6d 11 }

  condition:
    any of them
}