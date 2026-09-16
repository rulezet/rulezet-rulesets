rule TTP_XOR_WriteProcessMemory_3f68 {
  strings:
    $key_3f68 = { 68 1a [2] 5a 38 [2] 5c 0d [2] 72 0d [2] 4d 11 }

  condition:
    any of them
}