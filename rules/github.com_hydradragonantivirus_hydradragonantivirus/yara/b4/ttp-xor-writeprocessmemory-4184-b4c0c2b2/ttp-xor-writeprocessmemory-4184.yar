rule TTP_XOR_WriteProcessMemory_4184 {
  strings:
    $key_4184 = { 16 f6 [2] 24 d4 [2] 22 e1 [2] 0c e1 [2] 33 fd }

  condition:
    any of them
}