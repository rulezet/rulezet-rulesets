rule TTP_XOR_WriteProcessMemory_e947 {
  strings:
    $key_e947 = { be 35 [2] 8c 17 [2] 8a 22 [2] a4 22 [2] 9b 3e }

  condition:
    any of them
}