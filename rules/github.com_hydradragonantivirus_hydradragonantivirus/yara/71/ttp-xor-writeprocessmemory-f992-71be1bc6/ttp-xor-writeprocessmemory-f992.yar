rule TTP_XOR_WriteProcessMemory_f992 {
  strings:
    $key_f992 = { ae e0 [2] 9c c2 [2] 9a f7 [2] b4 f7 [2] 8b eb }

  condition:
    any of them
}