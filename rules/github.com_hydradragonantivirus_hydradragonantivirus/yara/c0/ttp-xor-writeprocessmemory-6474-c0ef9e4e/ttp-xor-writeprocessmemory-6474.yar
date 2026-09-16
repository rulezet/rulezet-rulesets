rule TTP_XOR_WriteProcessMemory_6474 {
  strings:
    $key_6474 = { 33 06 [2] 01 24 [2] 07 11 [2] 29 11 [2] 16 0d }

  condition:
    any of them
}