rule TTP_XOR_WriteProcessMemory_5918 {
  strings:
    $key_5918 = { 0e 6a [2] 3c 48 [2] 3a 7d [2] 14 7d [2] 2b 61 }

  condition:
    any of them
}