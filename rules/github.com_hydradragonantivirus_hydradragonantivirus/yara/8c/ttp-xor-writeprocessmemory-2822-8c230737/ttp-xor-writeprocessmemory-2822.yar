rule TTP_XOR_WriteProcessMemory_2822 {
  strings:
    $key_2822 = { 7f 50 [2] 4d 72 [2] 4b 47 [2] 65 47 [2] 5a 5b }

  condition:
    any of them
}