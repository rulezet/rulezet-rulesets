rule TTP_XOR_WriteProcessMemory_4033 {
  strings:
    $key_4033 = { 17 41 [2] 25 63 [2] 23 56 [2] 0d 56 [2] 32 4a }

  condition:
    any of them
}