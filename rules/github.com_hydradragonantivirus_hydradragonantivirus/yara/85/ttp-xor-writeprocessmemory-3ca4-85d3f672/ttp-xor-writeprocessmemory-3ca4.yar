rule TTP_XOR_WriteProcessMemory_3ca4 {
  strings:
    $key_3ca4 = { 6b d6 [2] 59 f4 [2] 5f c1 [2] 71 c1 [2] 4e dd }

  condition:
    any of them
}