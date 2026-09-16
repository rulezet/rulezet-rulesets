rule TTP_XOR_WriteProcessMemory_d08b {
  strings:
    $key_d08b = { 87 f9 [2] b5 db [2] b3 ee [2] 9d ee [2] a2 f2 }

  condition:
    any of them
}