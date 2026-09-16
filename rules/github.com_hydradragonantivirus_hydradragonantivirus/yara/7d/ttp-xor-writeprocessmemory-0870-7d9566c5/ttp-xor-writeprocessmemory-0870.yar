rule TTP_XOR_WriteProcessMemory_0870 {
  strings:
    $key_0870 = { 5f 02 [2] 6d 20 [2] 6b 15 [2] 45 15 [2] 7a 09 }

  condition:
    any of them
}