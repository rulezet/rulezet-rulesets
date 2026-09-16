rule TTP_XOR_WriteProcessMemory_1434 {
  strings:
    $key_1434 = { 43 46 [2] 71 64 [2] 77 51 [2] 59 51 [2] 66 4d }

  condition:
    any of them
}