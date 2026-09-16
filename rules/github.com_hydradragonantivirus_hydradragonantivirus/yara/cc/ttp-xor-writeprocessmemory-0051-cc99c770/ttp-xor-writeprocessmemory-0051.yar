rule TTP_XOR_WriteProcessMemory_0051 {
  strings:
    $key_0051 = { 57 23 [2] 65 01 [2] 63 34 [2] 4d 34 [2] 72 28 }

  condition:
    any of them
}