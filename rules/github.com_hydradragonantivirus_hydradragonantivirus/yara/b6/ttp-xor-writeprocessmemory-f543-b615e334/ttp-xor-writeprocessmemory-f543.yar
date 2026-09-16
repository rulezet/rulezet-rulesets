rule TTP_XOR_WriteProcessMemory_f543 {
  strings:
    $key_f543 = { a2 31 [2] 90 13 [2] 96 26 [2] b8 26 [2] 87 3a }

  condition:
    any of them
}