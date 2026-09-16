rule TTP_XOR_WriteProcessMemory_1ca2 {
  strings:
    $key_1ca2 = { 4b d0 [2] 79 f2 [2] 7f c7 [2] 51 c7 [2] 6e db }

  condition:
    any of them
}