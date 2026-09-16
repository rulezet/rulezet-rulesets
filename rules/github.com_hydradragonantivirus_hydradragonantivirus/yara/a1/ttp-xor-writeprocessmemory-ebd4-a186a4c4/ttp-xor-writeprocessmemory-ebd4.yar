rule TTP_XOR_WriteProcessMemory_ebd4 {
  strings:
    $key_ebd4 = { bc a6 [2] 8e 84 [2] 88 b1 [2] a6 b1 [2] 99 ad }

  condition:
    any of them
}