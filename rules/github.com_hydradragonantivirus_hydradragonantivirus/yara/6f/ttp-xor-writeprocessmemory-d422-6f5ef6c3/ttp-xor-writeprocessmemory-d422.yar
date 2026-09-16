rule TTP_XOR_WriteProcessMemory_d422 {
  strings:
    $key_d422 = { 83 50 [2] b1 72 [2] b7 47 [2] 99 47 [2] a6 5b }

  condition:
    any of them
}