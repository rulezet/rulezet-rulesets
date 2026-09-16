rule TTP_XOR_WriteProcessMemory_3b78 {
  strings:
    $key_3b78 = { 6c 0a [2] 5e 28 [2] 58 1d [2] 76 1d [2] 49 01 }

  condition:
    any of them
}