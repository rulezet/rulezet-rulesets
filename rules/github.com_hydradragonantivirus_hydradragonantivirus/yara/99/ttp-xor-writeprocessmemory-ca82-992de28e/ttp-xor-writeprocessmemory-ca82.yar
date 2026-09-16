rule TTP_XOR_WriteProcessMemory_ca82 {
  strings:
    $key_ca82 = { 9d f0 [2] af d2 [2] a9 e7 [2] 87 e7 [2] b8 fb }

  condition:
    any of them
}