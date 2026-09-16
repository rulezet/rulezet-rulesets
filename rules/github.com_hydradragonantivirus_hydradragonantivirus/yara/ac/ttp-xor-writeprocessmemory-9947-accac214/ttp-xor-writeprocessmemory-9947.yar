rule TTP_XOR_WriteProcessMemory_9947 {
  strings:
    $key_9947 = { ce 35 [2] fc 17 [2] fa 22 [2] d4 22 [2] eb 3e }

  condition:
    any of them
}