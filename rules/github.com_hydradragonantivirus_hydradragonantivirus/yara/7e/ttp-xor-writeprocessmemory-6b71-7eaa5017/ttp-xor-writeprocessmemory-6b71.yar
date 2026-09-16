rule TTP_XOR_WriteProcessMemory_6b71 {
  strings:
    $key_6b71 = { 3c 03 [2] 0e 21 [2] 08 14 [2] 26 14 [2] 19 08 }

  condition:
    any of them
}