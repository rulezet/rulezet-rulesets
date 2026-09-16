rule TTP_XOR_WriteProcessMemory_5021 {
  strings:
    $key_5021 = { 07 53 [2] 35 71 [2] 33 44 [2] 1d 44 [2] 22 58 }

  condition:
    any of them
}