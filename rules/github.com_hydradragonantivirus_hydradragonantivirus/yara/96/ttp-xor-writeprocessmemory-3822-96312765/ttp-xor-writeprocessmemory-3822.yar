rule TTP_XOR_WriteProcessMemory_3822 {
  strings:
    $key_3822 = { 6f 50 [2] 5d 72 [2] 5b 47 [2] 75 47 [2] 4a 5b }

  condition:
    any of them
}