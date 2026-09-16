rule TTP_XOR_WriteProcessMemory_10f1 {
  strings:
    $key_10f1 = { 47 83 [2] 75 a1 [2] 73 94 [2] 5d 94 [2] 62 88 }

  condition:
    any of them
}