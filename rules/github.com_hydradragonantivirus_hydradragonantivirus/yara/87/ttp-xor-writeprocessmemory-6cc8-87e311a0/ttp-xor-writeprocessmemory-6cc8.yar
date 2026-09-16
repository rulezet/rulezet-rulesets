rule TTP_XOR_WriteProcessMemory_6cc8 {
  strings:
    $key_6cc8 = { 3b ba [2] 09 98 [2] 0f ad [2] 21 ad [2] 1e b1 }

  condition:
    any of them
}