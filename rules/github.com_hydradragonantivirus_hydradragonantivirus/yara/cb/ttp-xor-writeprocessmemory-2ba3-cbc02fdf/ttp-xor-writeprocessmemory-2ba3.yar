rule TTP_XOR_WriteProcessMemory_2ba3 {
  strings:
    $key_2ba3 = { 7c d1 [2] 4e f3 [2] 48 c6 [2] 66 c6 [2] 59 da }

  condition:
    any of them
}