rule TTP_XOR_WriteProcessMemory_6c50 {
  strings:
    $key_6c50 = { 3b 22 [2] 09 00 [2] 0f 35 [2] 21 35 [2] 1e 29 }

  condition:
    any of them
}