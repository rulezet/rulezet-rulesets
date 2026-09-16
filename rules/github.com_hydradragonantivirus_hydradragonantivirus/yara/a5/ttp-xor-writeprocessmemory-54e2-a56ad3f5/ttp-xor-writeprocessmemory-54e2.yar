rule TTP_XOR_WriteProcessMemory_54e2 {
  strings:
    $key_54e2 = { 03 90 [2] 31 b2 [2] 37 87 [2] 19 87 [2] 26 9b }

  condition:
    any of them
}