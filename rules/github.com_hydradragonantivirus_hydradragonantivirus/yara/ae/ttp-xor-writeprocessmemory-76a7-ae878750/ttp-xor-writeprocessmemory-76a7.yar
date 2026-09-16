rule TTP_XOR_WriteProcessMemory_76a7 {
  strings:
    $key_76a7 = { 21 d5 [2] 13 f7 [2] 15 c2 [2] 3b c2 [2] 04 de }

  condition:
    any of them
}