rule TTP_XOR_WriteProcessMemory_2226 {
  strings:
    $key_2226 = { 75 54 [2] 47 76 [2] 41 43 [2] 6f 43 [2] 50 5f }

  condition:
    any of them
}