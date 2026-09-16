rule TTP_XOR_WriteProcessMemory_c301 {
  strings:
    $key_c301 = { 94 73 [2] a6 51 [2] a0 64 [2] 8e 64 [2] b1 78 }

  condition:
    any of them
}