rule TTP_XOR_WriteProcessMemory_0061 {
  strings:
    $key_0061 = { 57 13 [2] 65 31 [2] 63 04 [2] 4d 04 [2] 72 18 }

  condition:
    any of them
}