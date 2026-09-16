rule TTP_XOR_WriteProcessMemory_34f1 {
  strings:
    $key_34f1 = { 63 83 [2] 51 a1 [2] 57 94 [2] 79 94 [2] 46 88 }

  condition:
    any of them
}