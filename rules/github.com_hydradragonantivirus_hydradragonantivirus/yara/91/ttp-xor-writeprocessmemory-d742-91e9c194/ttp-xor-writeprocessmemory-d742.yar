rule TTP_XOR_WriteProcessMemory_d742 {
  strings:
    $key_d742 = { 80 30 [2] b2 12 [2] b4 27 [2] 9a 27 [2] a5 3b }

  condition:
    any of them
}