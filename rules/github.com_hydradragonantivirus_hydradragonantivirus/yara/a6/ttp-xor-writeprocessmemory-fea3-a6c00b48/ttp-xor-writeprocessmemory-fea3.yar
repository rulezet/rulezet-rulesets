rule TTP_XOR_WriteProcessMemory_fea3 {
  strings:
    $key_fea3 = { a9 d1 [2] 9b f3 [2] 9d c6 [2] b3 c6 [2] 8c da }

  condition:
    any of them
}