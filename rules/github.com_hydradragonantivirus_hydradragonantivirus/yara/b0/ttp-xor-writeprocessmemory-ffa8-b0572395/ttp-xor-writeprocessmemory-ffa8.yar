rule TTP_XOR_WriteProcessMemory_ffa8 {
  strings:
    $key_ffa8 = { a8 da [2] 9a f8 [2] 9c cd [2] b2 cd [2] 8d d1 }

  condition:
    any of them
}