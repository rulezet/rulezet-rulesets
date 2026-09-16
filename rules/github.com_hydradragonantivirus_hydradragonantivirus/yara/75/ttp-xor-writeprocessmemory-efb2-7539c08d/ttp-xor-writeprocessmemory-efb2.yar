rule TTP_XOR_WriteProcessMemory_efb2 {
  strings:
    $key_efb2 = { b8 c0 [2] 8a e2 [2] 8c d7 [2] a2 d7 [2] 9d cb }

  condition:
    any of them
}