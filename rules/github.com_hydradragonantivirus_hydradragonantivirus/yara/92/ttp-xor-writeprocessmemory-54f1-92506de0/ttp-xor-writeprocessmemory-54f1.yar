rule TTP_XOR_WriteProcessMemory_54f1 {
  strings:
    $key_54f1 = { 03 83 [2] 31 a1 [2] 37 94 [2] 19 94 [2] 26 88 }

  condition:
    any of them
}