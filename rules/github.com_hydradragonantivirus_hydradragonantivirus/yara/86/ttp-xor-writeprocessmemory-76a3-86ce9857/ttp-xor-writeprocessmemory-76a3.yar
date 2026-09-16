rule TTP_XOR_WriteProcessMemory_76a3 {
  strings:
    $key_76a3 = { 21 d1 [2] 13 f3 [2] 15 c6 [2] 3b c6 [2] 04 da }

  condition:
    any of them
}