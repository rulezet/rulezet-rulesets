rule TTP_XOR_WriteProcessMemory_74f1 {
  strings:
    $key_74f1 = { 23 83 [2] 11 a1 [2] 17 94 [2] 39 94 [2] 06 88 }

  condition:
    any of them
}