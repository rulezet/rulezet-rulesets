rule TTP_XOR_WriteProcessMemory_0166 {
  strings:
    $key_0166 = { 56 14 [2] 64 36 [2] 62 03 [2] 4c 03 [2] 73 1f }

  condition:
    any of them
}