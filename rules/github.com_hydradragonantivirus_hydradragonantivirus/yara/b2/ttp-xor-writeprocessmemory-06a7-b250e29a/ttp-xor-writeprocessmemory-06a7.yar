rule TTP_XOR_WriteProcessMemory_06a7 {
  strings:
    $key_06a7 = { 51 d5 [2] 63 f7 [2] 65 c2 [2] 4b c2 [2] 74 de }

  condition:
    any of them
}