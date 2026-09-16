rule TTP_XOR_WriteProcessMemory_d154 {
  strings:
    $key_d154 = { 86 26 [2] b4 04 [2] b2 31 [2] 9c 31 [2] a3 2d }

  condition:
    any of them
}