rule TTP_XOR_WriteProcessMemory_2761 {
  strings:
    $key_2761 = { 70 13 [2] 42 31 [2] 44 04 [2] 6a 04 [2] 55 18 }

  condition:
    any of them
}