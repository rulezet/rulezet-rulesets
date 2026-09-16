rule TTP_XOR_WriteProcessMemory_3770 {
  strings:
    $key_3770 = { 60 02 [2] 52 20 [2] 54 15 [2] 7a 15 [2] 45 09 }

  condition:
    any of them
}