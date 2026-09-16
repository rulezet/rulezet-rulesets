rule TTP_XOR_WriteProcessMemory_1014 {
  strings:
    $key_1014 = { 47 66 [2] 75 44 [2] 73 71 [2] 5d 71 [2] 62 6d }

  condition:
    any of them
}