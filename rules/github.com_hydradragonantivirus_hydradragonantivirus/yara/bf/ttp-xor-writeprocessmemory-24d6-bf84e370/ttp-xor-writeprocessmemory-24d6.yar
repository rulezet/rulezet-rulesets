rule TTP_XOR_WriteProcessMemory_24d6 {
  strings:
    $key_24d6 = { 73 a4 [2] 41 86 [2] 47 b3 [2] 69 b3 [2] 56 af }

  condition:
    any of them
}