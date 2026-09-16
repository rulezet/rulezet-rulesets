rule TTP_XOR_WriteProcessMemory_00f1 {
  strings:
    $key_00f1 = { 57 83 [2] 65 a1 [2] 63 94 [2] 4d 94 [2] 72 88 }

  condition:
    any of them
}