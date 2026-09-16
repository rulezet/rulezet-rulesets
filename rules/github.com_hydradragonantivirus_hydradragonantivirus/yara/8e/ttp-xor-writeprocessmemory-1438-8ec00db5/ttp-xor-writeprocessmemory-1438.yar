rule TTP_XOR_WriteProcessMemory_1438 {
  strings:
    $key_1438 = { 43 4a [2] 71 68 [2] 77 5d [2] 59 5d [2] 66 41 }

  condition:
    any of them
}