rule TTP_XOR_WriteProcessMemory_6433 {
  strings:
    $key_6433 = { 33 41 [2] 01 63 [2] 07 56 [2] 29 56 [2] 16 4a }

  condition:
    any of them
}