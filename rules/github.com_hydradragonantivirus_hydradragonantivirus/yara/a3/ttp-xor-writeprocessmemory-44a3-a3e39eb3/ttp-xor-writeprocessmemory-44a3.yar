rule TTP_XOR_WriteProcessMemory_44a3 {
  strings:
    $key_44a3 = { 13 d1 [2] 21 f3 [2] 27 c6 [2] 09 c6 [2] 36 da }

  condition:
    any of them
}