rule TTP_XOR_WriteProcessMemory_04a1 {
  strings:
    $key_04a1 = { 53 d3 [2] 61 f1 [2] 67 c4 [2] 49 c4 [2] 76 d8 }

  condition:
    any of them
}