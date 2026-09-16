rule TTP_XOR_WriteProcessMemory_d152 {
  strings:
    $key_d152 = { 86 20 [2] b4 02 [2] b2 37 [2] 9c 37 [2] a3 2b }

  condition:
    any of them
}