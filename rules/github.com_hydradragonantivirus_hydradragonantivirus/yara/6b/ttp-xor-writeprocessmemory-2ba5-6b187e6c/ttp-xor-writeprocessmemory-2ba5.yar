rule TTP_XOR_WriteProcessMemory_2ba5 {
  strings:
    $key_2ba5 = { 7c d7 [2] 4e f5 [2] 48 c0 [2] 66 c0 [2] 59 dc }

  condition:
    any of them
}