rule TTP_XOR_WriteProcessMemory_16e2 {
  strings:
    $key_16e2 = { 41 90 [2] 73 b2 [2] 75 87 [2] 5b 87 [2] 64 9b }

  condition:
    any of them
}