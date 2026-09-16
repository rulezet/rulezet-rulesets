rule TTP_XOR_WriteProcessMemory_0856 {
  strings:
    $key_0856 = { 5f 24 [2] 6d 06 [2] 6b 33 [2] 45 33 [2] 7a 2f }

  condition:
    any of them
}