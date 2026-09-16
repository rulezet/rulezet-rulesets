rule TTP_XOR_WriteProcessMemory_3fd6 {
  strings:
    $key_3fd6 = { 68 a4 [2] 5a 86 [2] 5c b3 [2] 72 b3 [2] 4d af }

  condition:
    any of them
}