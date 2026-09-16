rule TTP_XOR_WriteProcessMemory_3810 {
  strings:
    $key_3810 = { 6f 62 [2] 5d 40 [2] 5b 75 [2] 75 75 [2] 4a 69 }

  condition:
    any of them
}