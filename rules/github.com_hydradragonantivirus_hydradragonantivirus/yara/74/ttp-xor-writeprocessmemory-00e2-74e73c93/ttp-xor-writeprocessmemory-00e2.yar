rule TTP_XOR_WriteProcessMemory_00e2 {
  strings:
    $key_00e2 = { 57 90 [2] 65 b2 [2] 63 87 [2] 4d 87 [2] 72 9b }

  condition:
    any of them
}