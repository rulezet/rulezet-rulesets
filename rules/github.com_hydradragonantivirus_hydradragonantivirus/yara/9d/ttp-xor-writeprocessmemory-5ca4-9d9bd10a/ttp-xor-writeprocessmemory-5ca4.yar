rule TTP_XOR_WriteProcessMemory_5ca4 {
  strings:
    $key_5ca4 = { 0b d6 [2] 39 f4 [2] 3f c1 [2] 11 c1 [2] 2e dd }

  condition:
    any of them
}