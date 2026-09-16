rule TTP_XOR_WriteProcessMemory_00f5 {
  strings:
    $key_00f5 = { 57 87 [2] 65 a5 [2] 63 90 [2] 4d 90 [2] 72 8c }

  condition:
    any of them
}