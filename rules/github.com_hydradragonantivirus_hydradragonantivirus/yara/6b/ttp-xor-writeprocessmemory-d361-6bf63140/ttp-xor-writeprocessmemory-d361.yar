rule TTP_XOR_WriteProcessMemory_d361 {
  strings:
    $key_d361 = { 84 13 [2] b6 31 [2] b0 04 [2] 9e 04 [2] a1 18 }

  condition:
    any of them
}