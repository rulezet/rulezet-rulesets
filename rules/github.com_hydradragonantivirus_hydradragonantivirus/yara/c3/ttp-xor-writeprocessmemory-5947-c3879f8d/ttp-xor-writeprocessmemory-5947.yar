rule TTP_XOR_WriteProcessMemory_5947 {
  strings:
    $key_5947 = { 0e 35 [2] 3c 17 [2] 3a 22 [2] 14 22 [2] 2b 3e }

  condition:
    any of them
}