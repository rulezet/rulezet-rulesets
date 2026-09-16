rule TTP_XOR_WriteProcessMemory_5fe2 {
  strings:
    $key_5fe2 = { 08 90 [2] 3a b2 [2] 3c 87 [2] 12 87 [2] 2d 9b }

  condition:
    any of them
}