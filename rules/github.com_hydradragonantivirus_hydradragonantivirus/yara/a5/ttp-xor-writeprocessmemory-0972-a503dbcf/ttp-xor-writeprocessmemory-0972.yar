rule TTP_XOR_WriteProcessMemory_0972 {
  strings:
    $key_0972 = { 5e 00 [2] 6c 22 [2] 6a 17 [2] 44 17 [2] 7b 0b }

  condition:
    any of them
}