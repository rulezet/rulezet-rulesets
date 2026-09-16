rule TTP_XOR_WriteProcessMemory_0d65 {
  strings:
    $key_0d65 = { 5a 17 [2] 68 35 [2] 6e 00 [2] 40 00 [2] 7f 1c }

  condition:
    any of them
}