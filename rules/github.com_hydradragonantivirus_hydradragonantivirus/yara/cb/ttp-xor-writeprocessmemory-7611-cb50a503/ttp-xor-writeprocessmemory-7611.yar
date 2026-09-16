rule TTP_XOR_WriteProcessMemory_7611 {
  strings:
    $key_7611 = { 21 63 [2] 13 41 [2] 15 74 [2] 3b 74 [2] 04 68 }

  condition:
    any of them
}