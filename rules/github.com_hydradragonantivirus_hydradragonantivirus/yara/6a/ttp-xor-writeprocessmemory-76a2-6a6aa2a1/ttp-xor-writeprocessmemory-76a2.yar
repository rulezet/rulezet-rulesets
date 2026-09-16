rule TTP_XOR_WriteProcessMemory_76a2 {
  strings:
    $key_76a2 = { 21 d0 [2] 13 f2 [2] 15 c7 [2] 3b c7 [2] 04 db }

  condition:
    any of them
}