rule TTP_XOR_WriteProcessMemory_4401 {
  strings:
    $key_4401 = { 13 73 [2] 21 51 [2] 27 64 [2] 09 64 [2] 36 78 }

  condition:
    any of them
}