rule TTP_XOR_WriteProcessMemory_4718 {
  strings:
    $key_4718 = { 10 6a [2] 22 48 [2] 24 7d [2] 0a 7d [2] 35 61 }

  condition:
    any of them
}