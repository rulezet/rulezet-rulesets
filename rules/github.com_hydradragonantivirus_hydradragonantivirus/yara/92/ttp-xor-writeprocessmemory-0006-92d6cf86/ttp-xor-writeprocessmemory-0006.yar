rule TTP_XOR_WriteProcessMemory_0006 {
  strings:
    $key_0006 = { 57 74 [2] 65 56 [2] 63 63 [2] 4d 63 [2] 72 7f }

  condition:
    any of them
}