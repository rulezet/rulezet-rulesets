rule TTP_XOR_WriteProcessMemory_04d6 {
  strings:
    $key_04d6 = { 53 a4 [2] 61 86 [2] 67 b3 [2] 49 b3 [2] 76 af }

  condition:
    any of them
}