rule TTP_XOR_WriteProcessMemory_c344 {
  strings:
    $key_c344 = { 94 36 [2] a6 14 [2] a0 21 [2] 8e 21 [2] b1 3d }

  condition:
    any of them
}