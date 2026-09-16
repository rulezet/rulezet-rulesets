rule TTP_XOR_WriteProcessMemory_19e0 {
  strings:
    $key_19e0 = { 4e 92 [2] 7c b0 [2] 7a 85 [2] 54 85 [2] 6b 99 }

  condition:
    any of them
}