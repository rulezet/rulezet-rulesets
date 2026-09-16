rule TTP_XOR_WriteProcessMemory_1947 {
  strings:
    $key_1947 = { 4e 35 [2] 7c 17 [2] 7a 22 [2] 54 22 [2] 6b 3e }

  condition:
    any of them
}