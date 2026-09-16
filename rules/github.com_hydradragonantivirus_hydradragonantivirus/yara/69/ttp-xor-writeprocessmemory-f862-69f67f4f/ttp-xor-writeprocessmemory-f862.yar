rule TTP_XOR_WriteProcessMemory_f862 {
  strings:
    $key_f862 = { af 10 [2] 9d 32 [2] 9b 07 [2] b5 07 [2] 8a 1b }

  condition:
    any of them
}