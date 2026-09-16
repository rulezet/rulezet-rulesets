rule TTP_XOR_WriteProcessMemory_f363 {
  strings:
    $key_f363 = { a4 11 [2] 96 33 [2] 90 06 [2] be 06 [2] 81 1a }

  condition:
    any of them
}