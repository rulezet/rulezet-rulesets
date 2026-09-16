rule TTP_XOR_WriteProcessMemory_4226 {
  strings:
    $key_4226 = { 15 54 [2] 27 76 [2] 21 43 [2] 0f 43 [2] 30 5f }

  condition:
    any of them
}