rule TTP_XOR_WriteProcessMemory_7202 {
  strings:
    $key_7202 = { 25 70 [2] 17 52 [2] 11 67 [2] 3f 67 [2] 00 7b }

  condition:
    any of them
}