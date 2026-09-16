rule TTP_XOR_WriteProcessMemory_58b3 {
  strings:
    $key_58b3 = { 0f c1 [2] 3d e3 [2] 3b d6 [2] 15 d6 [2] 2a ca }

  condition:
    any of them
}