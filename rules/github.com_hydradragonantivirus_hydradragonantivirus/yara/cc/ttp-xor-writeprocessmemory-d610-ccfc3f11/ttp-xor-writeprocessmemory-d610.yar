rule TTP_XOR_WriteProcessMemory_d610 {
  strings:
    $key_d610 = { 81 62 [2] b3 40 [2] b5 75 [2] 9b 75 [2] a4 69 }

  condition:
    any of them
}