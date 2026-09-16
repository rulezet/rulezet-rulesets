rule TTP_XOR_WriteProcessMemory_e850 {
  strings:
    $key_e850 = { bf 22 [2] 8d 00 [2] 8b 35 [2] a5 35 [2] 9a 29 }

  condition:
    any of them
}