rule TTP_XOR_WriteProcessMemory_33e4 {
  strings:
    $key_33e4 = { 64 96 [2] 56 b4 [2] 50 81 [2] 7e 81 [2] 41 9d }

  condition:
    any of them
}