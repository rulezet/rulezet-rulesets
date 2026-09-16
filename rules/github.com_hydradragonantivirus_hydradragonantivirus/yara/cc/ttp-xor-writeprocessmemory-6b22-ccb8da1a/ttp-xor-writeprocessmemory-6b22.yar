rule TTP_XOR_WriteProcessMemory_6b22 {
  strings:
    $key_6b22 = { 3c 50 [2] 0e 72 [2] 08 47 [2] 26 47 [2] 19 5b }

  condition:
    any of them
}