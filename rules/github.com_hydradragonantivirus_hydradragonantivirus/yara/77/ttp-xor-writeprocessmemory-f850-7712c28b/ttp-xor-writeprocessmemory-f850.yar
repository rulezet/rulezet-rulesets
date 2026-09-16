rule TTP_XOR_WriteProcessMemory_f850 {
  strings:
    $key_f850 = { af 22 [2] 9d 00 [2] 9b 35 [2] b5 35 [2] 8a 29 }

  condition:
    any of them
}