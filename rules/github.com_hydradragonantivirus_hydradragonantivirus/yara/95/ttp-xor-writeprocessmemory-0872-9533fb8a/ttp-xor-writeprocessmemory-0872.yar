rule TTP_XOR_WriteProcessMemory_0872 {
  strings:
    $key_0872 = { 5f 00 [2] 6d 22 [2] 6b 17 [2] 45 17 [2] 7a 0b }

  condition:
    any of them
}