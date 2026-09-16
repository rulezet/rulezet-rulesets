rule TTP_XOR_WriteProcessMemory_16e4 {
  strings:
    $key_16e4 = { 41 96 [2] 73 b4 [2] 75 81 [2] 5b 81 [2] 64 9d }

  condition:
    any of them
}