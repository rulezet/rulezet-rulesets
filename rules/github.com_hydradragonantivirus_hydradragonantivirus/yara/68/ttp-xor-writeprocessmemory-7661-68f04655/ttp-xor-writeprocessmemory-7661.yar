rule TTP_XOR_WriteProcessMemory_7661 {
  strings:
    $key_7661 = { 21 13 [2] 13 31 [2] 15 04 [2] 3b 04 [2] 04 18 }

  condition:
    any of them
}