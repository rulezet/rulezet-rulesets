rule TTP_XOR_WriteProcessMemory_2233 {
  strings:
    $key_2233 = { 75 41 [2] 47 63 [2] 41 56 [2] 6f 56 [2] 50 4a }

  condition:
    any of them
}