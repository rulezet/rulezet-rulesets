rule TTP_XOR_WriteProcessMemory_4014 {
  strings:
    $key_4014 = { 17 66 [2] 25 44 [2] 23 71 [2] 0d 71 [2] 32 6d }

  condition:
    any of them
}