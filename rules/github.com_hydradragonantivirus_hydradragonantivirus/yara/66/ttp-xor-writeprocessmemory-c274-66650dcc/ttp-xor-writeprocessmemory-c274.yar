rule TTP_XOR_WriteProcessMemory_c274 {
  strings:
    $key_c274 = { 95 06 [2] a7 24 [2] a1 11 [2] 8f 11 [2] b0 0d }

  condition:
    any of them
}