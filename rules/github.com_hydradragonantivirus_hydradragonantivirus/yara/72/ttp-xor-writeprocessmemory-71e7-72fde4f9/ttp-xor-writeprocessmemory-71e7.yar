rule TTP_XOR_WriteProcessMemory_71e7 {
  strings:
    $key_71e7 = { 26 95 [2] 14 b7 [2] 12 82 [2] 3c 82 [2] 03 9e }

  condition:
    any of them
}