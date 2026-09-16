rule TTP_XOR_WriteProcessMemory_8cb7 {
  strings:
    $key_8cb7 = { db c5 [2] e9 e7 [2] ef d2 [2] c1 d2 [2] fe ce }

  condition:
    any of them
}