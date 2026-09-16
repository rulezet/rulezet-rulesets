rule TTP_XOR_WriteProcessMemory_3842 {
  strings:
    $key_3842 = { 6f 30 [2] 5d 12 [2] 5b 27 [2] 75 27 [2] 4a 3b }

  condition:
    any of them
}