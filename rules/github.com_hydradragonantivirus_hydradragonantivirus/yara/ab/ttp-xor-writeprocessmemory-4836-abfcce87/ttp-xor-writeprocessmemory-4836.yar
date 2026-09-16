rule TTP_XOR_WriteProcessMemory_4836 {
  strings:
    $key_4836 = { 1f 44 [2] 2d 66 [2] 2b 53 [2] 05 53 [2] 3a 4f }

  condition:
    any of them
}