rule TTP_XOR_WriteProcessMemory_3872 {
  strings:
    $key_3872 = { 6f 00 [2] 5d 22 [2] 5b 17 [2] 75 17 [2] 4a 0b }

  condition:
    any of them
}