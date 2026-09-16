rule TTP_XOR_WriteProcessMemory_d48b {
  strings:
    $key_d48b = { 83 f9 [2] b1 db [2] b7 ee [2] 99 ee [2] a6 f2 }

  condition:
    any of them
}