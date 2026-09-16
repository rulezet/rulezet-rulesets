rule TTP_XOR_WriteProcessMemory_00d4 {
  strings:
    $key_00d4 = { 57 a6 [2] 65 84 [2] 63 b1 [2] 4d b1 [2] 72 ad }

  condition:
    any of them
}