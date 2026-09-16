rule TTP_XOR_WriteProcessMemory_3ad6 {
  strings:
    $key_3ad6 = { 6d a4 [2] 5f 86 [2] 59 b3 [2] 77 b3 [2] 48 af }

  condition:
    any of them
}