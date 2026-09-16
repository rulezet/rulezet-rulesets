rule TTP_XOR_WriteProcessMemory_eee2 {
  strings:
    $key_eee2 = { b9 90 [2] 8b b2 [2] 8d 87 [2] a3 87 [2] 9c 9b }

  condition:
    any of them
}