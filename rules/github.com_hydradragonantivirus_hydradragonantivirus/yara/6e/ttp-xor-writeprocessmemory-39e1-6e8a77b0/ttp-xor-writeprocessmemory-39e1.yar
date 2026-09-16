rule TTP_XOR_WriteProcessMemory_39e1 {
  strings:
    $key_39e1 = { 6e 93 [2] 5c b1 [2] 5a 84 [2] 74 84 [2] 4b 98 }

  condition:
    any of them
}