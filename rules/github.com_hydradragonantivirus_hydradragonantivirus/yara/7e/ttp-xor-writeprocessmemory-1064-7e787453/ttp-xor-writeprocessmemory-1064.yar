rule TTP_XOR_WriteProcessMemory_1064 {
  strings:
    $key_1064 = { 47 16 [2] 75 34 [2] 73 01 [2] 5d 01 [2] 62 1d }

  condition:
    any of them
}