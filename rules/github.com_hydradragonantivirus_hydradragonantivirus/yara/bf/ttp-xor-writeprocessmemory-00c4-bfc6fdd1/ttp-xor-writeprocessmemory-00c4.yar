rule TTP_XOR_WriteProcessMemory_00c4 {
  strings:
    $key_00c4 = { 57 b6 [2] 65 94 [2] 63 a1 [2] 4d a1 [2] 72 bd }

  condition:
    any of them
}