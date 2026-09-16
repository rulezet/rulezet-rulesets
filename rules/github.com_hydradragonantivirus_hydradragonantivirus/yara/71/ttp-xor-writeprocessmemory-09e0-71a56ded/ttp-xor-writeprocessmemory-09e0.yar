rule TTP_XOR_WriteProcessMemory_09e0 {
  strings:
    $key_09e0 = { 5e 92 [2] 6c b0 [2] 6a 85 [2] 44 85 [2] 7b 99 }

  condition:
    any of them
}