rule TTP_XOR_WriteProcessMemory_20f1 {
  strings:
    $key_20f1 = { 77 83 [2] 45 a1 [2] 43 94 [2] 6d 94 [2] 52 88 }

  condition:
    any of them
}