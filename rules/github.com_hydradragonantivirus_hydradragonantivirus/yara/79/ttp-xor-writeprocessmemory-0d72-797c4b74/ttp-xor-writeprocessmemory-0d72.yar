rule TTP_XOR_WriteProcessMemory_0d72 {
  strings:
    $key_0d72 = { 5a 00 [2] 68 22 [2] 6e 17 [2] 40 17 [2] 7f 0b }

  condition:
    any of them
}