rule TTP_XOR_WriteProcessMemory_dbb2 {
  strings:
    $key_dbb2 = { 8c c0 [2] be e2 [2] b8 d7 [2] 96 d7 [2] a9 cb }

  condition:
    any of them
}