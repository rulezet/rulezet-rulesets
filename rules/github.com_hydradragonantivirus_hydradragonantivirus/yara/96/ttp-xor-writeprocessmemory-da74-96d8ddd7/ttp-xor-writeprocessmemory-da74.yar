rule TTP_XOR_WriteProcessMemory_da74 {
  strings:
    $key_da74 = { 8d 06 [2] bf 24 [2] b9 11 [2] 97 11 [2] a8 0d }

  condition:
    any of them
}