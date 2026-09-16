rule TTP_XOR_WriteProcessMemory_7f78 {
  strings:
    $key_7f78 = { 28 0a [2] 1a 28 [2] 1c 1d [2] 32 1d [2] 0d 01 }

  condition:
    any of them
}