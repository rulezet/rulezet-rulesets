rule TTP_XOR_WriteProcessMemory_f507 {
  strings:
    $key_f507 = { a2 75 [2] 90 57 [2] 96 62 [2] b8 62 [2] 87 7e }

  condition:
    any of them
}