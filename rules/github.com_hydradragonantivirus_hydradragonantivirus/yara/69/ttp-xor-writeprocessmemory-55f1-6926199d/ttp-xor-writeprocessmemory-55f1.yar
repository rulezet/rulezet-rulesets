rule TTP_XOR_WriteProcessMemory_55f1 {
  strings:
    $key_55f1 = { 02 83 [2] 30 a1 [2] 36 94 [2] 18 94 [2] 27 88 }

  condition:
    any of them
}