rule TTP_XOR_WriteProcessMemory_7947 {
  strings:
    $key_7947 = { 2e 35 [2] 1c 17 [2] 1a 22 [2] 34 22 [2] 0b 3e }

  condition:
    any of them
}