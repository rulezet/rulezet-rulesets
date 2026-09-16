rule TTP_XOR_WriteProcessMemory_d514 {
  strings:
    $key_d514 = { 82 66 [2] b0 44 [2] b6 71 [2] 98 71 [2] a7 6d }

  condition:
    any of them
}