rule TTP_XOR_WriteProcessMemory_7546 {
  strings:
    $key_7546 = { 22 34 [2] 10 16 [2] 16 23 [2] 38 23 [2] 07 3f }

  condition:
    any of them
}