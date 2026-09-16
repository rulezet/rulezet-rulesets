rule TTP_XOR_WriteProcessMemory_3f84 {
  strings:
    $key_3f84 = { 68 f6 [2] 5a d4 [2] 5c e1 [2] 72 e1 [2] 4d fd }

  condition:
    any of them
}