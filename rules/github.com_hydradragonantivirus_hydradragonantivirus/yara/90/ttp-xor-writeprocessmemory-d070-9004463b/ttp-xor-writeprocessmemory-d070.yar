rule TTP_XOR_WriteProcessMemory_d070 {
  strings:
    $key_d070 = { 87 02 [2] b5 20 [2] b3 15 [2] 9d 15 [2] a2 09 }

  condition:
    any of them
}