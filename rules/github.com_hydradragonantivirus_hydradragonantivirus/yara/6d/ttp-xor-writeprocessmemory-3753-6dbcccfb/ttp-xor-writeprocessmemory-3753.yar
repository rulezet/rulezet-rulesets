rule TTP_XOR_WriteProcessMemory_3753 {
  strings:
    $key_3753 = { 60 21 [2] 52 03 [2] 54 36 [2] 7a 36 [2] 45 2a }

  condition:
    any of them
}