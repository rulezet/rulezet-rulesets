rule TTP_XOR_WriteProcessMemory_6f78 {
  strings:
    $key_6f78 = { 38 0a [2] 0a 28 [2] 0c 1d [2] 22 1d [2] 1d 01 }

  condition:
    any of them
}