rule TTP_XOR_WriteProcessMemory_04b0 {
  strings:
    $key_04b0 = { 53 c2 [2] 61 e0 [2] 67 d5 [2] 49 d5 [2] 76 c9 }

  condition:
    any of them
}