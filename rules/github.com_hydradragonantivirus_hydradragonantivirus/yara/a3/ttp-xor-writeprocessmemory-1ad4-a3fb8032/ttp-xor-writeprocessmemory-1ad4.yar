rule TTP_XOR_WriteProcessMemory_1ad4 {
  strings:
    $key_1ad4 = { 4d a6 [2] 7f 84 [2] 79 b1 [2] 57 b1 [2] 68 ad }

  condition:
    any of them
}