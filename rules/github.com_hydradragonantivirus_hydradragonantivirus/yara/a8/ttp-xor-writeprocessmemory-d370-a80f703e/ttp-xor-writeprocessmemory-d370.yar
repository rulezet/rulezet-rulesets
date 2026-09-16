rule TTP_XOR_WriteProcessMemory_d370 {
  strings:
    $key_d370 = { 84 02 [2] b6 20 [2] b0 15 [2] 9e 15 [2] a1 09 }

  condition:
    any of them
}