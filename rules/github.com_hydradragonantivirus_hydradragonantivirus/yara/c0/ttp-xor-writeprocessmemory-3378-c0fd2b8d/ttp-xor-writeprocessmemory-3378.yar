rule TTP_XOR_WriteProcessMemory_3378 {
  strings:
    $key_3378 = { 64 0a [2] 56 28 [2] 50 1d [2] 7e 1d [2] 41 01 }

  condition:
    any of them
}