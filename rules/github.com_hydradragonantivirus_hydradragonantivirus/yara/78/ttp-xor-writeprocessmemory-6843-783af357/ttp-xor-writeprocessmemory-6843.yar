rule TTP_XOR_WriteProcessMemory_6843 {
  strings:
    $key_6843 = { 3f 31 [2] 0d 13 [2] 0b 26 [2] 25 26 [2] 1a 3a }

  condition:
    any of them
}