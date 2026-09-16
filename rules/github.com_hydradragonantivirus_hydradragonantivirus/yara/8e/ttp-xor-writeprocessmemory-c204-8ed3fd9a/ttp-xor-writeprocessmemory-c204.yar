rule TTP_XOR_WriteProcessMemory_c204 {
  strings:
    $key_c204 = { 95 76 [2] a7 54 [2] a1 61 [2] 8f 61 [2] b0 7d }

  condition:
    any of them
}