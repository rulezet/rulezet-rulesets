rule TTP_XOR_WriteProcessMemory_1080 {
  strings:
    $key_1080 = { 47 f2 [2] 75 d0 [2] 73 e5 [2] 5d e5 [2] 62 f9 }

  condition:
    any of them
}