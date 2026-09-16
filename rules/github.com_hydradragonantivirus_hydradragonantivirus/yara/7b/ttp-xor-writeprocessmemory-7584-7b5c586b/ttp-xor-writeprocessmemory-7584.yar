rule TTP_XOR_WriteProcessMemory_7584 {
  strings:
    $key_7584 = { 22 f6 [2] 10 d4 [2] 16 e1 [2] 38 e1 [2] 07 fd }

  condition:
    any of them
}