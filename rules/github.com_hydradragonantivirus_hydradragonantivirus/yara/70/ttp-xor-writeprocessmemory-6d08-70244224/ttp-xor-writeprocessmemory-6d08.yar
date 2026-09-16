rule TTP_XOR_WriteProcessMemory_6d08 {
  strings:
    $key_6d08 = { 3a 7a [2] 08 58 [2] 0e 6d [2] 20 6d [2] 1f 71 }

  condition:
    any of them
}