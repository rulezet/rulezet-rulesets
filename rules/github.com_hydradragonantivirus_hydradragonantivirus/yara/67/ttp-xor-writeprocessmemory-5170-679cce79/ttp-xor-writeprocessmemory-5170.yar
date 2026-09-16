rule TTP_XOR_WriteProcessMemory_5170 {
  strings:
    $key_5170 = { 06 02 [2] 34 20 [2] 32 15 [2] 1c 15 [2] 23 09 }

  condition:
    any of them
}