rule TTP_XOR_WriteProcessMemory_1420 {
  strings:
    $key_1420 = { 43 52 [2] 71 70 [2] 77 45 [2] 59 45 [2] 66 59 }

  condition:
    any of them
}