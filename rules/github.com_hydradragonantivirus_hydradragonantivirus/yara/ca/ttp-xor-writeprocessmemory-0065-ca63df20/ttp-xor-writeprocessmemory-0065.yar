rule TTP_XOR_WriteProcessMemory_0065 {
  strings:
    $key_0065 = { 57 17 [2] 65 35 [2] 63 00 [2] 4d 00 [2] 72 1c }

  condition:
    any of them
}