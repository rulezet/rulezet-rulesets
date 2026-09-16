rule TTP_XOR_WriteProcessMemory_3cc8 {
  strings:
    $key_3cc8 = { 6b ba [2] 59 98 [2] 5f ad [2] 71 ad [2] 4e b1 }

  condition:
    any of them
}