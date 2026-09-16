rule TTP_XOR_WriteProcessMemory_5111 {
  strings:
    $key_5111 = { 06 63 [2] 34 41 [2] 32 74 [2] 1c 74 [2] 23 68 }

  condition:
    any of them
}