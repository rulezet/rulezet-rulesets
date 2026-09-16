rule TTP_XOR_WriteProcessMemory_00c5 {
  strings:
    $key_00c5 = { 57 b7 [2] 65 95 [2] 63 a0 [2] 4d a0 [2] 72 bc }

  condition:
    any of them
}