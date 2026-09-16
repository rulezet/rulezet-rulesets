rule TTP_XOR_WriteProcessMemory_d20d {
  strings:
    $key_d20d = { 85 7f [2] b7 5d [2] b1 68 [2] 9f 68 [2] a0 74 }

  condition:
    any of them
}