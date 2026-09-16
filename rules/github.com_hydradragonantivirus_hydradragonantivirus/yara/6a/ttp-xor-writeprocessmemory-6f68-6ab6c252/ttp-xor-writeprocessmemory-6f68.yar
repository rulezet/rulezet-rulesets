rule TTP_XOR_WriteProcessMemory_6f68 {
  strings:
    $key_6f68 = { 38 1a [2] 0a 38 [2] 0c 0d [2] 22 0d [2] 1d 11 }

  condition:
    any of them
}