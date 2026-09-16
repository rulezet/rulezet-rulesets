rule TTP_XOR_WriteProcessMemory_e006 {
  strings:
    $key_e006 = { b7 74 [2] 85 56 [2] 83 63 [2] ad 63 [2] 92 7f }

  condition:
    any of them
}