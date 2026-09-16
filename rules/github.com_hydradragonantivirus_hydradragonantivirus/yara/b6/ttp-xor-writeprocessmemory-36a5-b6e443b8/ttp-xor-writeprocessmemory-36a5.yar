rule TTP_XOR_WriteProcessMemory_36a5 {
  strings:
    $key_36a5 = { 61 d7 [2] 53 f5 [2] 55 c0 [2] 7b c0 [2] 44 dc }

  condition:
    any of them
}