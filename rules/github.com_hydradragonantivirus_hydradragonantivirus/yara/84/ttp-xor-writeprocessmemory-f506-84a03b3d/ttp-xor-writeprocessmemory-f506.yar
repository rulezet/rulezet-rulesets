rule TTP_XOR_WriteProcessMemory_f506 {
  strings:
    $key_f506 = { a2 74 [2] 90 56 [2] 96 63 [2] b8 63 [2] 87 7f }

  condition:
    any of them
}