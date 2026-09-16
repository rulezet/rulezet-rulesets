rule TTP_XOR_WriteProcessMemory_f553 {
  strings:
    $key_f553 = { a2 21 [2] 90 03 [2] 96 36 [2] b8 36 [2] 87 2a }

  condition:
    any of them
}