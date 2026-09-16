rule TTP_XOR_WriteProcessMemory_0002 {
  strings:
    $key_0002 = { 57 70 [2] 65 52 [2] 63 67 [2] 4d 67 [2] 72 7b }

  condition:
    any of them
}