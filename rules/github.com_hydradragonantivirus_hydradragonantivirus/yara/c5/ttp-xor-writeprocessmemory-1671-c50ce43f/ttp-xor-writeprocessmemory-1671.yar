rule TTP_XOR_WriteProcessMemory_1671 {
  strings:
    $key_1671 = { 41 03 [2] 73 21 [2] 75 14 [2] 5b 14 [2] 64 08 }

  condition:
    any of them
}