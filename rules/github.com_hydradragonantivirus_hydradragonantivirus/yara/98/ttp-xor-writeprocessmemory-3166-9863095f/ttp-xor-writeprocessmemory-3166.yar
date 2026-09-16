rule TTP_XOR_WriteProcessMemory_3166 {
  strings:
    $key_3166 = { 66 14 [2] 54 36 [2] 52 03 [2] 7c 03 [2] 43 1f }

  condition:
    any of them
}