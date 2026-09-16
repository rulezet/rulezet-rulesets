rule TTP_XOR_WriteProcessMemory_7ee1 {
  strings:
    $key_7ee1 = { 29 93 [2] 1b b1 [2] 1d 84 [2] 33 84 [2] 0c 98 }

  condition:
    any of them
}