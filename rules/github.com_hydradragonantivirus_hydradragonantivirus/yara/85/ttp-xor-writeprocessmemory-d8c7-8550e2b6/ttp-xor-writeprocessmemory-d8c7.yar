rule TTP_XOR_WriteProcessMemory_d8c7 {
  strings:
    $key_d8c7 = { 8f b5 [2] bd 97 [2] bb a2 [2] 95 a2 [2] aa be }

  condition:
    any of them
}