rule TTP_XOR_WriteProcessMemory_6c72 {
  strings:
    $key_6c72 = { 3b 00 [2] 09 22 [2] 0f 17 [2] 21 17 [2] 1e 0b }

  condition:
    any of them
}