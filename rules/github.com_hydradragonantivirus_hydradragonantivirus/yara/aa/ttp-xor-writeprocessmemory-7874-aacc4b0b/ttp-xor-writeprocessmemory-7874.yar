rule TTP_XOR_WriteProcessMemory_7874 {
  strings:
    $key_7874 = { 2f 06 [2] 1d 24 [2] 1b 11 [2] 35 11 [2] 0a 0d }

  condition:
    any of them
}