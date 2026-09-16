rule TTP_XOR_WriteProcessMemory_6811 {
  strings:
    $key_6811 = { 3f 63 [2] 0d 41 [2] 0b 74 [2] 25 74 [2] 1a 68 }

  condition:
    any of them
}