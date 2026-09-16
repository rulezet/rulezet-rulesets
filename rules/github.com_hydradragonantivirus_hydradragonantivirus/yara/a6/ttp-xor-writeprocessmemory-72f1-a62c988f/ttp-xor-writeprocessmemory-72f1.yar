rule TTP_XOR_WriteProcessMemory_72f1 {
  strings:
    $key_72f1 = { 25 83 [2] 17 a1 [2] 11 94 [2] 3f 94 [2] 00 88 }

  condition:
    any of them
}