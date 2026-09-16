rule TTP_XOR_WriteProcessMemory_6ee1 {
  strings:
    $key_6ee1 = { 39 93 [2] 0b b1 [2] 0d 84 [2] 23 84 [2] 1c 98 }

  condition:
    any of them
}