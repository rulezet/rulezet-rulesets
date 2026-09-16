rule TTP_XOR_WriteProcessMemory_3b71 {
  strings:
    $key_3b71 = { 6c 03 [2] 5e 21 [2] 58 14 [2] 76 14 [2] 49 08 }

  condition:
    any of them
}