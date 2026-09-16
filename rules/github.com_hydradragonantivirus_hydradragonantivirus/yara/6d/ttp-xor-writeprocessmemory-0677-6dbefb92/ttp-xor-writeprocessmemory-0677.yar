rule TTP_XOR_WriteProcessMemory_0677 {
  strings:
    $key_0677 = { 51 05 [2] 63 27 [2] 65 12 [2] 4b 12 [2] 74 0e }

  condition:
    any of them
}