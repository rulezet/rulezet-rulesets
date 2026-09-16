rule TTP_XOR_WriteProcessMemory_e950 {
  strings:
    $key_e950 = { be 22 [2] 8c 00 [2] 8a 35 [2] a4 35 [2] 9b 29 }

  condition:
    any of them
}