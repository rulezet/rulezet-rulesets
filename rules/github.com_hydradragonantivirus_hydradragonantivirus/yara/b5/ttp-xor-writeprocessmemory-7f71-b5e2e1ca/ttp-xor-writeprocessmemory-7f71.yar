rule TTP_XOR_WriteProcessMemory_7f71 {
  strings:
    $key_7f71 = { 28 03 [2] 1a 21 [2] 1c 14 [2] 32 14 [2] 0d 08 }

  condition:
    any of them
}