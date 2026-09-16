rule TTP_XOR_WriteProcessMemory_76a8 {
  strings:
    $key_76a8 = { 21 da [2] 13 f8 [2] 15 cd [2] 3b cd [2] 04 d1 }

  condition:
    any of them
}