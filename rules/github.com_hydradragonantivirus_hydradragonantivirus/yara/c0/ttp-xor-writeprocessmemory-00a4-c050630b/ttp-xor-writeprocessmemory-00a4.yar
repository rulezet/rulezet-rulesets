rule TTP_XOR_WriteProcessMemory_00a4 {
  strings:
    $key_00a4 = { 57 d6 [2] 65 f4 [2] 63 c1 [2] 4d c1 [2] 72 dd }

  condition:
    any of them
}