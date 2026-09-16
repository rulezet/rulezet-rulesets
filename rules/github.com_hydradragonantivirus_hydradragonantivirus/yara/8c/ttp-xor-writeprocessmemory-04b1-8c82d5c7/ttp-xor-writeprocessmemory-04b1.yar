rule TTP_XOR_WriteProcessMemory_04b1 {
  strings:
    $key_04b1 = { 53 c3 [2] 61 e1 [2] 67 d4 [2] 49 d4 [2] 76 c8 }

  condition:
    any of them
}