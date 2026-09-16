rule TTP_XOR_WriteProcessMemory_f521 {
  strings:
    $key_f521 = { a2 53 [2] 90 71 [2] 96 44 [2] b8 44 [2] 87 58 }

  condition:
    any of them
}