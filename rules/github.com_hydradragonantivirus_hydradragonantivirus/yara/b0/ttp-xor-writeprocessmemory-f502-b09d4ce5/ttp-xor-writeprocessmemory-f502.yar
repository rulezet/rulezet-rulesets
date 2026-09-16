rule TTP_XOR_WriteProcessMemory_f502 {
  strings:
    $key_f502 = { a2 70 [2] 90 52 [2] 96 67 [2] b8 67 [2] 87 7b }

  condition:
    any of them
}