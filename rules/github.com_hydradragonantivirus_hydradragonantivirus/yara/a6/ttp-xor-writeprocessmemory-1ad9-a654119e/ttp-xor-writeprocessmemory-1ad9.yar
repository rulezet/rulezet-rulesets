rule TTP_XOR_WriteProcessMemory_1ad9 {
  strings:
    $key_1ad9 = { 4d ab [2] 7f 89 [2] 79 bc [2] 57 bc [2] 68 a0 }

  condition:
    any of them
}