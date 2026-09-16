rule TTP_XOR_WriteProcessMemory_0042 {
  strings:
    $key_0042 = { 57 30 [2] 65 12 [2] 63 27 [2] 4d 27 [2] 72 3b }

  condition:
    any of them
}