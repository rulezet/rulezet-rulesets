rule TTP_XOR_WriteProcessMemory_c234 {
  strings:
    $key_c234 = { 95 46 [2] a7 64 [2] a1 51 [2] 8f 51 [2] b0 4d }

  condition:
    any of them
}