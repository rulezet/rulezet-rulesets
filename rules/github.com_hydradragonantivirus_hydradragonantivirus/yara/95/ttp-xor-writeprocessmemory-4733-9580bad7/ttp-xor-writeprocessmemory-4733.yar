rule TTP_XOR_WriteProcessMemory_4733 {
  strings:
    $key_4733 = { 10 41 [2] 22 63 [2] 24 56 [2] 0a 56 [2] 35 4a }

  condition:
    any of them
}