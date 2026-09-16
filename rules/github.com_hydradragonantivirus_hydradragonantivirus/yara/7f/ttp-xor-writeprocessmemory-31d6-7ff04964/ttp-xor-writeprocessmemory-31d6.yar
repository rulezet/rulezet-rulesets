rule TTP_XOR_WriteProcessMemory_31d6 {
  strings:
    $key_31d6 = { 66 a4 [2] 54 86 [2] 52 b3 [2] 7c b3 [2] 43 af }

  condition:
    any of them
}