rule TTP_XOR_WriteProcessMemory_6273 {
  strings:
    $key_6273 = { 35 01 [2] 07 23 [2] 01 16 [2] 2f 16 [2] 10 0a }

  condition:
    any of them
}