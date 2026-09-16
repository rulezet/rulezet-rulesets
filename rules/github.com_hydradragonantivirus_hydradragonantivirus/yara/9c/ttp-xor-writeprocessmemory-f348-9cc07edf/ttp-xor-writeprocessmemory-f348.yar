rule TTP_XOR_WriteProcessMemory_f348 {
  strings:
    $key_f348 = { a4 3a [2] 96 18 [2] 90 2d [2] be 2d [2] 81 31 }

  condition:
    any of them
}