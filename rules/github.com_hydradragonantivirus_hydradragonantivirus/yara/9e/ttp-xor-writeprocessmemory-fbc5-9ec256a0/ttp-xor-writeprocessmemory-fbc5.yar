rule TTP_XOR_WriteProcessMemory_fbc5 {
  strings:
    $key_fbc5 = { ac b7 [2] 9e 95 [2] 98 a0 [2] b6 a0 [2] 89 bc }

  condition:
    any of them
}