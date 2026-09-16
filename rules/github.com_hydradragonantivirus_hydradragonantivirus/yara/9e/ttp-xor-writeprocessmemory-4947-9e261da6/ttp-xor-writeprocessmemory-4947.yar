rule TTP_XOR_WriteProcessMemory_4947 {
  strings:
    $key_4947 = { 1e 35 [2] 2c 17 [2] 2a 22 [2] 04 22 [2] 3b 3e }

  condition:
    any of them
}