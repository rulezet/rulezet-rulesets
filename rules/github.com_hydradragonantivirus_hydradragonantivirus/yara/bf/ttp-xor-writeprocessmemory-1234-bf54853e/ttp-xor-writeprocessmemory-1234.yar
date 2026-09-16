rule TTP_XOR_WriteProcessMemory_1234 {
  strings:
    $key_1234 = { 45 46 [2] 77 64 [2] 71 51 [2] 5f 51 [2] 60 4d }

  condition:
    any of them
}