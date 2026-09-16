rule TTP_XOR_WriteProcessMemory_6ee2 {
  strings:
    $key_6ee2 = { 39 90 [2] 0b b2 [2] 0d 87 [2] 23 87 [2] 1c 9b }

  condition:
    any of them
}