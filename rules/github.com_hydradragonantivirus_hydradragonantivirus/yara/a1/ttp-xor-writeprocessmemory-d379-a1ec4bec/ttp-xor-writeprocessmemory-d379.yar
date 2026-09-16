rule TTP_XOR_WriteProcessMemory_d379 {
  strings:
    $key_d379 = { 84 0b [2] b6 29 [2] b0 1c [2] 9e 1c [2] a1 00 }

  condition:
    any of them
}