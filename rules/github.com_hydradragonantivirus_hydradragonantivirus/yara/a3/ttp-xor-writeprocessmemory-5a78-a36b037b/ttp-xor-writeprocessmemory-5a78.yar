rule TTP_XOR_WriteProcessMemory_5a78 {
  strings:
    $key_5a78 = { 0d 0a [2] 3f 28 [2] 39 1d [2] 17 1d [2] 28 01 }

  condition:
    any of them
}