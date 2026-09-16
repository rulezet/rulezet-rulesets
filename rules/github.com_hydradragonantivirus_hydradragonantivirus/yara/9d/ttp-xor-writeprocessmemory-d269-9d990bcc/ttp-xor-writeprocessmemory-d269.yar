rule TTP_XOR_WriteProcessMemory_d269 {
  strings:
    $key_d269 = { 85 1b [2] b7 39 [2] b1 0c [2] 9f 0c [2] a0 10 }

  condition:
    any of them
}