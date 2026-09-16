rule TTP_XOR_WriteProcessMemory_2108 {
  strings:
    $key_2108 = { 76 7a [2] 44 58 [2] 42 6d [2] 6c 6d [2] 53 71 }

  condition:
    any of them
}