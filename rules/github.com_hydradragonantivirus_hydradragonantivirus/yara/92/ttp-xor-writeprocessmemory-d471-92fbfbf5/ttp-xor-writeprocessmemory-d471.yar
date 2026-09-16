rule TTP_XOR_WriteProcessMemory_d471 {
  strings:
    $key_d471 = { 83 03 [2] b1 21 [2] b7 14 [2] 99 14 [2] a6 08 }

  condition:
    any of them
}