rule TTP_XOR_WriteProcessMemory_c285 {
  strings:
    $key_c285 = { 95 f7 [2] a7 d5 [2] a1 e0 [2] 8f e0 [2] b0 fc }

  condition:
    any of them
}