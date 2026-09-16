rule TTP_XOR_WriteProcessMemory_fc80 {
  strings:
    $key_fc80 = { ab f2 [2] 99 d0 [2] 9f e5 [2] b1 e5 [2] 8e f9 }

  condition:
    any of them
}