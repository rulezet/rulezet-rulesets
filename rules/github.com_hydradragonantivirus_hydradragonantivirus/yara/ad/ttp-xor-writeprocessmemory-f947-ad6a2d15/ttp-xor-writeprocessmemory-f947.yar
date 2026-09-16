rule TTP_XOR_WriteProcessMemory_f947 {
  strings:
    $key_f947 = { ae 35 [2] 9c 17 [2] 9a 22 [2] b4 22 [2] 8b 3e }

  condition:
    any of them
}