rule TTP_XOR_WriteProcessMemory_d331 {
  strings:
    $key_d331 = { 84 43 [2] b6 61 [2] b0 54 [2] 9e 54 [2] a1 48 }

  condition:
    any of them
}