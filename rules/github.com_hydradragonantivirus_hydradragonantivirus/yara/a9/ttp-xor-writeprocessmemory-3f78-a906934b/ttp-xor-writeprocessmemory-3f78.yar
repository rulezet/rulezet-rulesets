rule TTP_XOR_WriteProcessMemory_3f78 {
  strings:
    $key_3f78 = { 68 0a [2] 5a 28 [2] 5c 1d [2] 72 1d [2] 4d 01 }

  condition:
    any of them
}