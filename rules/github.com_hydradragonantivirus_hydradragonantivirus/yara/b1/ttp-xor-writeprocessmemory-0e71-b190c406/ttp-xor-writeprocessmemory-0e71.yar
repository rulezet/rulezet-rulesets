rule TTP_XOR_WriteProcessMemory_0e71 {
  strings:
    $key_0e71 = { 59 03 [2] 6b 21 [2] 6d 14 [2] 43 14 [2] 7c 08 }

  condition:
    any of them
}