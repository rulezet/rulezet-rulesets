rule TTP_XOR_WriteProcessMemory_06b1 {
  strings:
    $key_06b1 = { 51 c3 [2] 63 e1 [2] 65 d4 [2] 4b d4 [2] 74 c8 }

  condition:
    any of them
}