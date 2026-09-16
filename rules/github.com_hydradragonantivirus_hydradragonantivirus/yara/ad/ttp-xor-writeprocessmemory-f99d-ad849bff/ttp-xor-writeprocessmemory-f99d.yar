rule TTP_XOR_WriteProcessMemory_f99d {
  strings:
    $key_f99d = { ae ef [2] 9c cd [2] 9a f8 [2] b4 f8 [2] 8b e4 }

  condition:
    any of them
}