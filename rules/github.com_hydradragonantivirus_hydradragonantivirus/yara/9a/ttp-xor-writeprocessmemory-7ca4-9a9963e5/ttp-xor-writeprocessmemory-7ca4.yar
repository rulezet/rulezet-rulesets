rule TTP_XOR_WriteProcessMemory_7ca4 {
  strings:
    $key_7ca4 = { 2b d6 [2] 19 f4 [2] 1f c1 [2] 31 c1 [2] 0e dd }

  condition:
    any of them
}