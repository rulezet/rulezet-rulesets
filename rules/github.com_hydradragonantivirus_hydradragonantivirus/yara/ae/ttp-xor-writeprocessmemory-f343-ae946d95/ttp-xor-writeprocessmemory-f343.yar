rule TTP_XOR_WriteProcessMemory_f343 {
  strings:
    $key_f343 = { a4 31 [2] 96 13 [2] 90 26 [2] be 26 [2] 81 3a }

  condition:
    any of them
}