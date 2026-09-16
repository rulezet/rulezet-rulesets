rule TTP_XOR_WriteProcessMemory_c766 {
  strings:
    $key_c766 = { 90 14 [2] a2 36 [2] a4 03 [2] 8a 03 [2] b5 1f }

  condition:
    any of them
}