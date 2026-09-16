rule TTP_XOR_WriteProcessMemory_d5ac {
  strings:
    $key_d5ac = { 82 de [2] b0 fc [2] b6 c9 [2] 98 c9 [2] a7 d5 }

  condition:
    any of them
}