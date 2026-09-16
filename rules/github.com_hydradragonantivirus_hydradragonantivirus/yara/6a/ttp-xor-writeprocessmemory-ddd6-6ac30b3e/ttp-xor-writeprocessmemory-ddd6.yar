rule TTP_XOR_WriteProcessMemory_ddd6 {
  strings:
    $key_ddd6 = { 8a a4 [2] b8 86 [2] be b3 [2] 90 b3 [2] af af }

  condition:
    any of them
}