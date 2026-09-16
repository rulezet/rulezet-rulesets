rule TTP_XOR_WriteProcessMemory_4803 {
  strings:
    $key_4803 = { 1f 71 [2] 2d 53 [2] 2b 66 [2] 05 66 [2] 3a 7a }

  condition:
    any of them
}