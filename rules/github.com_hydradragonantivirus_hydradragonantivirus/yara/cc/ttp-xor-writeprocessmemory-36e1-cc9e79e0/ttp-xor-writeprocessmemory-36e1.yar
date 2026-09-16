rule TTP_XOR_WriteProcessMemory_36e1 {
  strings:
    $key_36e1 = { 61 93 [2] 53 b1 [2] 55 84 [2] 7b 84 [2] 44 98 }

  condition:
    any of them
}