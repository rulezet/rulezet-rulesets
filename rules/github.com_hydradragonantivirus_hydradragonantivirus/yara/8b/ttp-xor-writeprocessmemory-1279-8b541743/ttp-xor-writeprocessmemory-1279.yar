rule TTP_XOR_WriteProcessMemory_1279 {
  strings:
    $key_1279 = { 45 0b [2] 77 29 [2] 71 1c [2] 5f 1c [2] 60 00 }

  condition:
    any of them
}