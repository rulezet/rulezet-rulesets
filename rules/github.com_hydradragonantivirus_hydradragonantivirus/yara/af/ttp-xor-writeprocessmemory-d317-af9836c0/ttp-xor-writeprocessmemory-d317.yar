rule TTP_XOR_WriteProcessMemory_d317 {
  strings:
    $key_d317 = { 84 65 [2] b6 47 [2] b0 72 [2] 9e 72 [2] a1 6e }

  condition:
    any of them
}