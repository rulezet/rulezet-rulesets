rule TTP_XOR_WriteProcessMemory_09e1 {
  strings:
    $key_09e1 = { 5e 93 [2] 6c b1 [2] 6a 84 [2] 44 84 [2] 7b 98 }

  condition:
    any of them
}