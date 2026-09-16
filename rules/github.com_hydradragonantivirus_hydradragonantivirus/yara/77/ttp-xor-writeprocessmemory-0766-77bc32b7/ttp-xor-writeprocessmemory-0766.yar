rule TTP_XOR_WriteProcessMemory_0766 {
  strings:
    $key_0766 = { 50 14 [2] 62 36 [2] 64 03 [2] 4a 03 [2] 75 1f }

  condition:
    any of them
}