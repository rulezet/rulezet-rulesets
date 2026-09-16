rule TTP_XOR_WriteProcessMemory_2fe1 {
  strings:
    $key_2fe1 = { 78 93 [2] 4a b1 [2] 4c 84 [2] 62 84 [2] 5d 98 }

  condition:
    any of them
}