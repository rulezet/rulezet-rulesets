rule TTP_XOR_WriteProcessMemory_0a71 {
  strings:
    $key_0a71 = { 5d 03 [2] 6f 21 [2] 69 14 [2] 47 14 [2] 78 08 }

  condition:
    any of them
}