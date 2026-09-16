rule TTP_XOR_WriteProcessMemory_2f06 {
  strings:
    $key_2f06 = { 78 74 [2] 4a 56 [2] 4c 63 [2] 62 63 [2] 5d 7f }

  condition:
    any of them
}