rule TTP_XOR_WriteProcessMemory_d313 {
  strings:
    $key_d313 = { 84 61 [2] b6 43 [2] b0 76 [2] 9e 76 [2] a1 6a }

  condition:
    any of them
}