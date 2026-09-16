rule TTP_XOR_WriteProcessMemory_00f3 {
  strings:
    $key_00f3 = { 57 81 [2] 65 a3 [2] 63 96 [2] 4d 96 [2] 72 8a }

  condition:
    any of them
}