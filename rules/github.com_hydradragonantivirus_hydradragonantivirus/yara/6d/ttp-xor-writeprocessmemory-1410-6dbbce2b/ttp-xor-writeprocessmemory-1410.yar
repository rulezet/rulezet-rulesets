rule TTP_XOR_WriteProcessMemory_1410 {
  strings:
    $key_1410 = { 43 62 [2] 71 40 [2] 77 75 [2] 59 75 [2] 66 69 }

  condition:
    any of them
}