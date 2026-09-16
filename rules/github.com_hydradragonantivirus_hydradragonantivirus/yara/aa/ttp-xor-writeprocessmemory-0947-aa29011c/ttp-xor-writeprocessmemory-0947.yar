rule TTP_XOR_WriteProcessMemory_0947 {
  strings:
    $key_0947 = { 5e 35 [2] 6c 17 [2] 6a 22 [2] 44 22 [2] 7b 3e }

  condition:
    any of them
}