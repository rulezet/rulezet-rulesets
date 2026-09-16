rule TTP_XOR_WriteProcessMemory_1868 {
  strings:
    $key_1868 = { 4f 1a [2] 7d 38 [2] 7b 0d [2] 55 0d [2] 6a 11 }

  condition:
    any of them
}