rule TTP_XOR_WriteProcessMemory_0ee2 {
  strings:
    $key_0ee2 = { 59 90 [2] 6b b2 [2] 6d 87 [2] 43 87 [2] 7c 9b }

  condition:
    any of them
}