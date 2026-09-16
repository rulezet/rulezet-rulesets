rule TTP_XOR_WriteProcessMemory_6861 {
  strings:
    $key_6861 = { 3f 13 [2] 0d 31 [2] 0b 04 [2] 25 04 [2] 1a 18 }

  condition:
    any of them
}