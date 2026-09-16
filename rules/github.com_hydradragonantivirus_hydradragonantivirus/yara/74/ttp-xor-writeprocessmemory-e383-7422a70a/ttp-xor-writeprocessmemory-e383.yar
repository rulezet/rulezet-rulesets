rule TTP_XOR_WriteProcessMemory_e383 {
  strings:
    $key_e383 = { b4 f1 [2] 86 d3 [2] 80 e6 [2] ae e6 [2] 91 fa }

  condition:
    any of them
}