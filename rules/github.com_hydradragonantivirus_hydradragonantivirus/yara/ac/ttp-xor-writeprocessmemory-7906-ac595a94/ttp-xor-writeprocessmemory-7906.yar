rule TTP_XOR_WriteProcessMemory_7906 {
  strings:
    $key_7906 = { 2e 74 [2] 1c 56 [2] 1a 63 [2] 34 63 [2] 0b 7f }

  condition:
    any of them
}