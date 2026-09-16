rule TTP_XOR_WriteProcessMemory_e706 {
  strings:
    $key_e706 = { b0 74 [2] 82 56 [2] 84 63 [2] aa 63 [2] 95 7f }

  condition:
    any of them
}