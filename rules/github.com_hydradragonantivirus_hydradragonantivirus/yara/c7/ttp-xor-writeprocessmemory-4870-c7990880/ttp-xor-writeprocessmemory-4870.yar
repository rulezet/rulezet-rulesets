rule TTP_XOR_WriteProcessMemory_4870 {
  strings:
    $key_4870 = { 1f 02 [2] 2d 20 [2] 2b 15 [2] 05 15 [2] 3a 09 }

  condition:
    any of them
}