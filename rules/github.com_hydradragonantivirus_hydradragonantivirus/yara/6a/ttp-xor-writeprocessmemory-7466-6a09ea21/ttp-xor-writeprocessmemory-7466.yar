rule TTP_XOR_WriteProcessMemory_7466 {
  strings:
    $key_7466 = { 23 14 [2] 11 36 [2] 17 03 [2] 39 03 [2] 06 1f }

  condition:
    any of them
}