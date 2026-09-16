rule TTP_XOR_WriteProcessMemory_32e7 {
  strings:
    $key_32e7 = { 65 95 [2] 57 b7 [2] 51 82 [2] 7f 82 [2] 40 9e }

  condition:
    any of them
}