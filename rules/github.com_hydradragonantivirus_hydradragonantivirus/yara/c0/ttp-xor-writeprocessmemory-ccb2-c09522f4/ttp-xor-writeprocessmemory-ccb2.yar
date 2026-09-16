rule TTP_XOR_WriteProcessMemory_ccb2 {
  strings:
    $key_ccb2 = { 9b c0 [2] a9 e2 [2] af d7 [2] 81 d7 [2] be cb }

  condition:
    any of them
}