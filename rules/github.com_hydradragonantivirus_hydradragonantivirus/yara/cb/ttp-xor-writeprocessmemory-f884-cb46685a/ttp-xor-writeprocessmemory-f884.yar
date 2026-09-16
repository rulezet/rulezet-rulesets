rule TTP_XOR_WriteProcessMemory_f884 {
  strings:
    $key_f884 = { af f6 [2] 9d d4 [2] 9b e1 [2] b5 e1 [2] 8a fd }

  condition:
    any of them
}