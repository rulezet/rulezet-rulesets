rule TTP_XOR_WriteProcessMemory_0878 {
  strings:
    $key_0878 = { 5f 0a [2] 6d 28 [2] 6b 1d [2] 45 1d [2] 7a 01 }

  condition:
    any of them
}