rule TTP_XOR_WriteProcessMemory_fea7 {
  strings:
    $key_fea7 = { a9 d5 [2] 9b f7 [2] 9d c2 [2] b3 c2 [2] 8c de }

  condition:
    any of them
}