rule TTP_XOR_WriteProcessMemory_eca6 {
  strings:
    $key_eca6 = { bb d4 [2] 89 f6 [2] 8f c3 [2] a1 c3 [2] 9e df }

  condition:
    any of them
}