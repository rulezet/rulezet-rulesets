rule TTP_XOR_WriteProcessMemory_d382 {
  strings:
    $key_d382 = { 84 f0 [2] b6 d2 [2] b0 e7 [2] 9e e7 [2] a1 fb }

  condition:
    any of them
}