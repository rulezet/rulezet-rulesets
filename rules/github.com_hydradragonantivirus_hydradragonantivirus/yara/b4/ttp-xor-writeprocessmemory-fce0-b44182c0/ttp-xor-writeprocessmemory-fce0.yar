rule TTP_XOR_WriteProcessMemory_fce0 {
  strings:
    $key_fce0 = { ab 92 [2] 99 b0 [2] 9f 85 [2] b1 85 [2] 8e 99 }

  condition:
    any of them
}