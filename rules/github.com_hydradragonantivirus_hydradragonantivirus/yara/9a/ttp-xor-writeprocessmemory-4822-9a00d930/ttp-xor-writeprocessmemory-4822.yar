rule TTP_XOR_WriteProcessMemory_4822 {
  strings:
    $key_4822 = { 1f 50 [2] 2d 72 [2] 2b 47 [2] 05 47 [2] 3a 5b }

  condition:
    any of them
}