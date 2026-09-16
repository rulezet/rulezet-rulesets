rule TTP_XOR_WriteProcessMemory_1c21 {
  strings:
    $key_1c21 = { 4b 53 [2] 79 71 [2] 7f 44 [2] 51 44 [2] 6e 58 }

  condition:
    any of them
}