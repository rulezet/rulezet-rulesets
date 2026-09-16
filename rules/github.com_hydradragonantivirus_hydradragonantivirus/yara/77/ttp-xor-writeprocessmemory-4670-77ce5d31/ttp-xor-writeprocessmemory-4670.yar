rule TTP_XOR_WriteProcessMemory_4670 {
  strings:
    $key_4670 = { 11 02 [2] 23 20 [2] 25 15 [2] 0b 15 [2] 34 09 }

  condition:
    any of them
}