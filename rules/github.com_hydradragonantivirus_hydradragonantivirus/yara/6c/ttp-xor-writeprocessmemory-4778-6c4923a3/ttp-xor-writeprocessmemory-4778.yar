rule TTP_XOR_WriteProcessMemory_4778 {
  strings:
    $key_4778 = { 10 0a [2] 22 28 [2] 24 1d [2] 0a 1d [2] 35 01 }

  condition:
    any of them
}