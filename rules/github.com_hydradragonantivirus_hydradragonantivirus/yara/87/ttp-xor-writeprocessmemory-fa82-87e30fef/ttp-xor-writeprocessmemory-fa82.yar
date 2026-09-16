rule TTP_XOR_WriteProcessMemory_fa82 {
  strings:
    $key_fa82 = { ad f0 [2] 9f d2 [2] 99 e7 [2] b7 e7 [2] 88 fb }

  condition:
    any of them
}