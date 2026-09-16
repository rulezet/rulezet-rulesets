rule TTP_XOR_WriteProcessMemory_19e1 {
  strings:
    $key_19e1 = { 4e 93 [2] 7c b1 [2] 7a 84 [2] 54 84 [2] 6b 98 }

  condition:
    any of them
}