rule TTP_XOR_WriteProcessMemory_5d08 {
  strings:
    $key_5d08 = { 0a 7a [2] 38 58 [2] 3e 6d [2] 10 6d [2] 2f 71 }

  condition:
    any of them
}