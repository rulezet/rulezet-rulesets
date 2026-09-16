rule TTP_XOR_WriteProcessMemory_0243 {
  strings:
    $key_0243 = { 55 31 [2] 67 13 [2] 61 26 [2] 4f 26 [2] 70 3a }

  condition:
    any of them
}