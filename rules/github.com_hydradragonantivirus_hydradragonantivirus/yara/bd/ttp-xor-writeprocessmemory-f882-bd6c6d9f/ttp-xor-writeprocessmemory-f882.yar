rule TTP_XOR_WriteProcessMemory_f882 {
  strings:
    $key_f882 = { af f0 [2] 9d d2 [2] 9b e7 [2] b5 e7 [2] 8a fb }

  condition:
    any of them
}