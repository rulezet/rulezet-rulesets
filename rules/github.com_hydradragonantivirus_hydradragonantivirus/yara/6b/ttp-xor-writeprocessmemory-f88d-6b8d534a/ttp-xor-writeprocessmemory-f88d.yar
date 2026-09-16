rule TTP_XOR_WriteProcessMemory_f88d {
  strings:
    $key_f88d = { af ff [2] 9d dd [2] 9b e8 [2] b5 e8 [2] 8a f4 }

  condition:
    any of them
}