rule TTP_XOR_WriteProcessMemory_6ca4 {
  strings:
    $key_6ca4 = { 3b d6 [2] 09 f4 [2] 0f c1 [2] 21 c1 [2] 1e dd }

  condition:
    any of them
}