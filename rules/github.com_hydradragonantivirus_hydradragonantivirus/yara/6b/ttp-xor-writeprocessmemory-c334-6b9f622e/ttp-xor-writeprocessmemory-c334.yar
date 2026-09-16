rule TTP_XOR_WriteProcessMemory_c334 {
  strings:
    $key_c334 = { 94 46 [2] a6 64 [2] a0 51 [2] 8e 51 [2] b1 4d }

  condition:
    any of them
}