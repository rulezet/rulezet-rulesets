rule TTP_XOR_WriteProcessMemory_6871 {
  strings:
    $key_6871 = { 3f 03 [2] 0d 21 [2] 0b 14 [2] 25 14 [2] 1a 08 }

  condition:
    any of them
}