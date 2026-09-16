rule TTP_XOR_WriteProcessMemory_6284 {
  strings:
    $key_6284 = { 35 f6 [2] 07 d4 [2] 01 e1 [2] 2f e1 [2] 10 fd }

  condition:
    any of them
}