rule TTP_XOR_WriteProcessMemory_17a7 {
  strings:
    $key_17a7 = { 40 d5 [2] 72 f7 [2] 74 c2 [2] 5a c2 [2] 65 de }

  condition:
    any of them
}