rule TTP_XOR_WriteProcessMemory_d771 {
  strings:
    $key_d771 = { 80 03 [2] b2 21 [2] b4 14 [2] 9a 14 [2] a5 08 }

  condition:
    any of them
}