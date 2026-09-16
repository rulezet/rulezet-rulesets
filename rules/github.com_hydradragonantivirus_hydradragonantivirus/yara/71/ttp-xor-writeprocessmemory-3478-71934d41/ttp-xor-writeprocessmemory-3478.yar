rule TTP_XOR_WriteProcessMemory_3478 {
  strings:
    $key_3478 = { 63 0a [2] 51 28 [2] 57 1d [2] 79 1d [2] 46 01 }

  condition:
    any of them
}