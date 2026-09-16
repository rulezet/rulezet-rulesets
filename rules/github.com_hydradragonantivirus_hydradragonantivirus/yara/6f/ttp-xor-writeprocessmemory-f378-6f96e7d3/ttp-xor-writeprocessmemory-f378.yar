rule TTP_XOR_WriteProcessMemory_f378 {
  strings:
    $key_f378 = { a4 0a [2] 96 28 [2] 90 1d [2] be 1d [2] 81 01 }

  condition:
    any of them
}