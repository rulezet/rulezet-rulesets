rule TTP_XOR_WriteProcessMemory_7fc3 {
  strings:
    $key_7fc3 = { 28 b1 [2] 1a 93 [2] 1c a6 [2] 32 a6 [2] 0d ba }

  condition:
    any of them
}