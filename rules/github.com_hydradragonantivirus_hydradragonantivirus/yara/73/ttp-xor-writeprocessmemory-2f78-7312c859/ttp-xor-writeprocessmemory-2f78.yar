rule TTP_XOR_WriteProcessMemory_2f78 {
  strings:
    $key_2f78 = { 78 0a [2] 4a 28 [2] 4c 1d [2] 62 1d [2] 5d 01 }

  condition:
    any of them
}