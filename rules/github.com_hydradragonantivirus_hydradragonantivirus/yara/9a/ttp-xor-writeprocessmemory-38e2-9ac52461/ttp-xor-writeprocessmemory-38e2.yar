rule TTP_XOR_WriteProcessMemory_38e2 {
  strings:
    $key_38e2 = { 6f 90 [2] 5d b2 [2] 5b 87 [2] 75 87 [2] 4a 9b }

  condition:
    any of them
}