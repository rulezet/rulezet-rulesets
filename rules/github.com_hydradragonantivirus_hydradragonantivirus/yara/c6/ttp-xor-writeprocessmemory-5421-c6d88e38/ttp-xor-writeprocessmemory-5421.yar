rule TTP_XOR_WriteProcessMemory_5421 {
  strings:
    $key_5421 = { 03 53 [2] 31 71 [2] 37 44 [2] 19 44 [2] 26 58 }

  condition:
    any of them
}