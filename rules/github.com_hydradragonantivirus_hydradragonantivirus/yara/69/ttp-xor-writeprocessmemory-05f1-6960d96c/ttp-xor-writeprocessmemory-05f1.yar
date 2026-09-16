rule TTP_XOR_WriteProcessMemory_05f1 {
  strings:
    $key_05f1 = { 52 83 [2] 60 a1 [2] 66 94 [2] 48 94 [2] 77 88 }

  condition:
    any of them
}