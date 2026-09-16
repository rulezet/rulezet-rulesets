rule TTP_XOR_WriteProcessMemory_0d02 {
  strings:
    $key_0d02 = { 5a 70 [2] 68 52 [2] 6e 67 [2] 40 67 [2] 7f 7b }

  condition:
    any of them
}