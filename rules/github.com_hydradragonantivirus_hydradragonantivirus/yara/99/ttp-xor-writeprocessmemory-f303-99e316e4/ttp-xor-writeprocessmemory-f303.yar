rule TTP_XOR_WriteProcessMemory_f303 {
  strings:
    $key_f303 = { a4 71 [2] 96 53 [2] 90 66 [2] be 66 [2] 81 7a }

  condition:
    any of them
}