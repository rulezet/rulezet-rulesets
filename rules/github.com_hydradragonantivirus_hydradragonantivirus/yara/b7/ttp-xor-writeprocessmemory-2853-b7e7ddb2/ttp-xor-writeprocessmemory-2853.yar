rule TTP_XOR_WriteProcessMemory_2853 {
  strings:
    $key_2853 = { 7f 21 [2] 4d 03 [2] 4b 36 [2] 65 36 [2] 5a 2a }

  condition:
    any of them
}