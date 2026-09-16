rule TTP_XOR_WriteProcessMemory_c267 {
  strings:
    $key_c267 = { 95 15 [2] a7 37 [2] a1 02 [2] 8f 02 [2] b0 1e }

  condition:
    any of them
}