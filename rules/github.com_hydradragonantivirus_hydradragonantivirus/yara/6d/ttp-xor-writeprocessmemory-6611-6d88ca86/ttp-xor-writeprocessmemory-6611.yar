rule TTP_XOR_WriteProcessMemory_6611 {
  strings:
    $key_6611 = { 31 63 [2] 03 41 [2] 05 74 [2] 2b 74 [2] 14 68 }

  condition:
    any of them
}