rule TTP_XOR_WriteProcessMemory_d702 {
  strings:
    $key_d702 = { 80 70 [2] b2 52 [2] b4 67 [2] 9a 67 [2] a5 7b }

  condition:
    any of them
}