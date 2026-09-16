rule TTP_XOR_WriteProcessMemory_d754 {
  strings:
    $key_d754 = { 80 26 [2] b2 04 [2] b4 31 [2] 9a 31 [2] a5 2d }

  condition:
    any of them
}