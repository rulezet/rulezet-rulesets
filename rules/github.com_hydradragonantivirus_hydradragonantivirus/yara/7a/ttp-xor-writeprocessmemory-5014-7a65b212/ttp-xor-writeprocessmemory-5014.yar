rule TTP_XOR_WriteProcessMemory_5014 {
  strings:
    $key_5014 = { 07 66 [2] 35 44 [2] 33 71 [2] 1d 71 [2] 22 6d }

  condition:
    any of them
}