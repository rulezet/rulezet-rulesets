rule TTP_XOR_WriteProcessMemory_7c21 {
  strings:
    $key_7c21 = { 2b 53 [2] 19 71 [2] 1f 44 [2] 31 44 [2] 0e 58 }

  condition:
    any of them
}