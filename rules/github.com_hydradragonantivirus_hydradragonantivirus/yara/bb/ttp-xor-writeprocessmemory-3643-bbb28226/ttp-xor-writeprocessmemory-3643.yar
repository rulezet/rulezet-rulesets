rule TTP_XOR_WriteProcessMemory_3643 {
  strings:
    $key_3643 = { 61 31 [2] 53 13 [2] 55 26 [2] 7b 26 [2] 44 3a }

  condition:
    any of them
}