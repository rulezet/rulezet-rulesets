rule TTP_XOR_WriteProcessMemory_5571 {
  strings:
    $key_5571 = { 02 03 [2] 30 21 [2] 36 14 [2] 18 14 [2] 27 08 }

  condition:
    any of them
}