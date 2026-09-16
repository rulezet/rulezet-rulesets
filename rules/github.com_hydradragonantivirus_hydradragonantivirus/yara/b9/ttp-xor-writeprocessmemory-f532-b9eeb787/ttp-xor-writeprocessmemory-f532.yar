rule TTP_XOR_WriteProcessMemory_f532 {
  strings:
    $key_f532 = { a2 40 [2] 90 62 [2] 96 57 [2] b8 57 [2] 87 4b }

  condition:
    any of them
}