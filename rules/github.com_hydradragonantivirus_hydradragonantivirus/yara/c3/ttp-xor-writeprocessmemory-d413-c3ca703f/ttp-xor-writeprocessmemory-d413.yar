rule TTP_XOR_WriteProcessMemory_d413 {
  strings:
    $key_d413 = { 83 61 [2] b1 43 [2] b7 76 [2] 99 76 [2] a6 6a }

  condition:
    any of them
}