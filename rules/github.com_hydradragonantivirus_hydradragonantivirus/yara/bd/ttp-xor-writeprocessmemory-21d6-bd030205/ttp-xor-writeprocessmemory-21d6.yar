rule TTP_XOR_WriteProcessMemory_21d6 {
  strings:
    $key_21d6 = { 76 a4 [2] 44 86 [2] 42 b3 [2] 6c b3 [2] 53 af }

  condition:
    any of them
}