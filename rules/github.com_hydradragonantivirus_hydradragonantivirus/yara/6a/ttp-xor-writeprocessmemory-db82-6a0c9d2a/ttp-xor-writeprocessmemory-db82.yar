rule TTP_XOR_WriteProcessMemory_db82 {
  strings:
    $key_db82 = { 8c f0 [2] be d2 [2] b8 e7 [2] 96 e7 [2] a9 fb }

  condition:
    any of them
}