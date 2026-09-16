rule TTP_XOR_WriteProcessMemory_1ad1 {
  strings:
    $key_1ad1 = { 4d a3 [2] 7f 81 [2] 79 b4 [2] 57 b4 [2] 68 a8 }

  condition:
    any of them
}