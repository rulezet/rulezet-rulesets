rule TTP_XOR_WriteProcessMemory_c774 {
  strings:
    $key_c774 = { 90 06 [2] a2 24 [2] a4 11 [2] 8a 11 [2] b5 0d }

  condition:
    any of them
}