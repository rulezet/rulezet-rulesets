rule TTP_XOR_WriteProcessMemory_2508 {
  strings:
    $key_2508 = { 72 7a [2] 40 58 [2] 46 6d [2] 68 6d [2] 57 71 }

  condition:
    any of them
}