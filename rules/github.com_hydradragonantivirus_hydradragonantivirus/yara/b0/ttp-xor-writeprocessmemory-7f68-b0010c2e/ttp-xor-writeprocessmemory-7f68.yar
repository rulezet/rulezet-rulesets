rule TTP_XOR_WriteProcessMemory_7f68 {
  strings:
    $key_7f68 = { 28 1a [2] 1a 38 [2] 1c 0d [2] 32 0d [2] 0d 11 }

  condition:
    any of them
}