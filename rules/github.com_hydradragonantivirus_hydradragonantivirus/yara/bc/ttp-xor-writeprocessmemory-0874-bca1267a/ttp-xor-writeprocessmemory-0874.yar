rule TTP_XOR_WriteProcessMemory_0874 {
  strings:
    $key_0874 = { 5f 06 [2] 6d 24 [2] 6b 11 [2] 45 11 [2] 7a 0d }

  condition:
    any of them
}