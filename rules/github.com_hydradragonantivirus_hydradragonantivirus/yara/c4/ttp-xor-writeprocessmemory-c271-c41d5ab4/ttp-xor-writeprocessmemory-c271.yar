rule TTP_XOR_WriteProcessMemory_c271 {
  strings:
    $key_c271 = { 95 03 [2] a7 21 [2] a1 14 [2] 8f 14 [2] b0 08 }

  condition:
    any of them
}