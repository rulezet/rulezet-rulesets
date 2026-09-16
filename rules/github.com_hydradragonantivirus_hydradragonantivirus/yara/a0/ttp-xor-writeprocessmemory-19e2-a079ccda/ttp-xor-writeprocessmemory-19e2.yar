rule TTP_XOR_WriteProcessMemory_19e2 {
  strings:
    $key_19e2 = { 4e 90 [2] 7c b2 [2] 7a 87 [2] 54 87 [2] 6b 9b }

  condition:
    any of them
}