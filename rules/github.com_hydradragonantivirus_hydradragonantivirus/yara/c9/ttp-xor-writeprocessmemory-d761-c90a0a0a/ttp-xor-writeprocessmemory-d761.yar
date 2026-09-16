rule TTP_XOR_WriteProcessMemory_d761 {
  strings:
    $key_d761 = { 80 13 [2] b2 31 [2] b4 04 [2] 9a 04 [2] a5 18 }

  condition:
    any of them
}