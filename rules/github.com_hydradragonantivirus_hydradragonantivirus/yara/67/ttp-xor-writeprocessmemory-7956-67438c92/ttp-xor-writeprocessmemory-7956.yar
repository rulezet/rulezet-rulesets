rule TTP_XOR_WriteProcessMemory_7956 {
  strings:
    $key_7956 = { 2e 24 [2] 1c 06 [2] 1a 33 [2] 34 33 [2] 0b 2f }

  condition:
    any of them
}