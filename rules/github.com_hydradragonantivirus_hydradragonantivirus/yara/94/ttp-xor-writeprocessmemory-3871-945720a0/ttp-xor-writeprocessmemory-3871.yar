rule TTP_XOR_WriteProcessMemory_3871 {
  strings:
    $key_3871 = { 6f 03 [2] 5d 21 [2] 5b 14 [2] 75 14 [2] 4a 08 }

  condition:
    any of them
}