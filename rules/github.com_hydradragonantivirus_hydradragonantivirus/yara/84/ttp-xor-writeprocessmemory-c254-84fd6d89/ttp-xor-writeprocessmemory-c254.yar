rule TTP_XOR_WriteProcessMemory_c254 {
  strings:
    $key_c254 = { 95 26 [2] a7 04 [2] a1 31 [2] 8f 31 [2] b0 2d }

  condition:
    any of them
}