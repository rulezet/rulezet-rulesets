rule TTP_XOR_WriteProcessMemory_d774 {
  strings:
    $key_d774 = { 80 06 [2] b2 24 [2] b4 11 [2] 9a 11 [2] a5 0d }

  condition:
    any of them
}