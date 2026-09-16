rule TTP_XOR_WriteProcessMemory_ebd2 {
  strings:
    $key_ebd2 = { bc a0 [2] 8e 82 [2] 88 b7 [2] a6 b7 [2] 99 ab }

  condition:
    any of them
}