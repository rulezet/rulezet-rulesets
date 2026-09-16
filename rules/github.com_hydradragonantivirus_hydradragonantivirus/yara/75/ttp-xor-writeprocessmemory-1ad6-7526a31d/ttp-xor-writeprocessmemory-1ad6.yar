rule TTP_XOR_WriteProcessMemory_1ad6 {
  strings:
    $key_1ad6 = { 4d a4 [2] 7f 86 [2] 79 b3 [2] 57 b3 [2] 68 af }

  condition:
    any of them
}