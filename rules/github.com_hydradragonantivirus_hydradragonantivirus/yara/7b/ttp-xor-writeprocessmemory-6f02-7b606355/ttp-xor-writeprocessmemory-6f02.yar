rule TTP_XOR_WriteProcessMemory_6f02 {
  strings:
    $key_6f02 = { 38 70 [2] 0a 52 [2] 0c 67 [2] 22 67 [2] 1d 7b }

  condition:
    any of them
}