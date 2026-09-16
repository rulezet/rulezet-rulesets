rule TTP_XOR_WriteProcessMemory_fea8 {
  strings:
    $key_fea8 = { a9 da [2] 9b f8 [2] 9d cd [2] b3 cd [2] 8c d1 }

  condition:
    any of them
}