rule TTP_XOR_WriteProcessMemory_f822 {
  strings:
    $key_f822 = { af 50 [2] 9d 72 [2] 9b 47 [2] b5 47 [2] 8a 5b }

  condition:
    any of them
}