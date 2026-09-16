rule TTP_XOR_WriteProcessMemory_f368 {
  strings:
    $key_f368 = { a4 1a [2] 96 38 [2] 90 0d [2] be 0d [2] 81 11 }

  condition:
    any of them
}