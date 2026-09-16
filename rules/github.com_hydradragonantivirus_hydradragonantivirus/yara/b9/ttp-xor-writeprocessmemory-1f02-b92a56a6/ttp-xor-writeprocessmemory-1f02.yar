rule TTP_XOR_WriteProcessMemory_1f02 {
  strings:
    $key_1f02 = { 48 70 [2] 7a 52 [2] 7c 67 [2] 52 67 [2] 6d 7b }

  condition:
    any of them
}