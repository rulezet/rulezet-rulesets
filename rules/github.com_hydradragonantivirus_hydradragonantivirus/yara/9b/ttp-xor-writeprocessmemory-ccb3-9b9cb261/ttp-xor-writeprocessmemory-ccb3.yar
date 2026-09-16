rule TTP_XOR_WriteProcessMemory_ccb3 {
  strings:
    $key_ccb3 = { 9b c1 [2] a9 e3 [2] af d6 [2] 81 d6 [2] be ca }

  condition:
    any of them
}