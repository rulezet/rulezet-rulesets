rule TTP_XOR_WriteProcessMemory_7822 {
  strings:
    $key_7822 = { 2f 50 [2] 1d 72 [2] 1b 47 [2] 35 47 [2] 0a 5b }

  condition:
    any of them
}