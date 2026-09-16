rule TTP_XOR_WriteProcessMemory_c114 {
  strings:
    $key_c114 = { 96 66 [2] a4 44 [2] a2 71 [2] 8c 71 [2] b3 6d }

  condition:
    any of them
}