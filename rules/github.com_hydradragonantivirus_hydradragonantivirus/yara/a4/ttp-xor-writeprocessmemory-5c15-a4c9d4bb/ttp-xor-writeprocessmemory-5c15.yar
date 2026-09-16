rule TTP_XOR_WriteProcessMemory_5c15 {
  strings:
    $key_5c15 = { 0b 67 [2] 39 45 [2] 3f 70 [2] 11 70 [2] 2e 6c }

  condition:
    any of them
}