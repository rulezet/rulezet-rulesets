rule TTP_XOR_WriteProcessMemory_1e71 {
  strings:
    $key_1e71 = { 49 03 [2] 7b 21 [2] 7d 14 [2] 53 14 [2] 6c 08 }

  condition:
    any of them
}