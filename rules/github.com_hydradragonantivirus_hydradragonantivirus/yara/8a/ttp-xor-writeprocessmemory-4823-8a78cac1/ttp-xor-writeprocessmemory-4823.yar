rule TTP_XOR_WriteProcessMemory_4823 {
  strings:
    $key_4823 = { 1f 51 [2] 2d 73 [2] 2b 46 [2] 05 46 [2] 3a 5a }

  condition:
    any of them
}