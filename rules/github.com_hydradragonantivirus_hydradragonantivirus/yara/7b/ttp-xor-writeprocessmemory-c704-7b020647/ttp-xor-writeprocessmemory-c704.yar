rule TTP_XOR_WriteProcessMemory_c704 {
  strings:
    $key_c704 = { 90 76 [2] a2 54 [2] a4 61 [2] 8a 61 [2] b5 7d }

  condition:
    any of them
}