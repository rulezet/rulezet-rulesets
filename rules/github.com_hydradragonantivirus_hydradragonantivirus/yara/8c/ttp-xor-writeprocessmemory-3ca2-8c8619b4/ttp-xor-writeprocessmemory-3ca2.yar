rule TTP_XOR_WriteProcessMemory_3ca2 {
  strings:
    $key_3ca2 = { 6b d0 [2] 59 f2 [2] 5f c7 [2] 71 c7 [2] 4e db }

  condition:
    any of them
}