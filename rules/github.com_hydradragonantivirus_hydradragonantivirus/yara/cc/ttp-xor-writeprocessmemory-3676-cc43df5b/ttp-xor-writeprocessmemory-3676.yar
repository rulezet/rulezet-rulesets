rule TTP_XOR_WriteProcessMemory_3676 {
  strings:
    $key_3676 = { 61 04 [2] 53 26 [2] 55 13 [2] 7b 13 [2] 44 0f }

  condition:
    any of them
}