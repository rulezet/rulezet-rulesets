rule TTP_XOR_WriteProcessMemory_04a7 {
  strings:
    $key_04a7 = { 53 d5 [2] 61 f7 [2] 67 c2 [2] 49 c2 [2] 76 de }

  condition:
    any of them
}