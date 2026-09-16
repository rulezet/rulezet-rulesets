rule TTP_XOR_WriteProcessMemory_21e2 {
  strings:
    $key_21e2 = { 76 90 [2] 44 b2 [2] 42 87 [2] 6c 87 [2] 53 9b }

  condition:
    any of them
}