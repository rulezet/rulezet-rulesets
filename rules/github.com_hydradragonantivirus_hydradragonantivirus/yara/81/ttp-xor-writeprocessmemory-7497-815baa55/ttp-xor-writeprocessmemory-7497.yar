rule TTP_XOR_WriteProcessMemory_7497 {
  strings:
    $key_7497 = { 23 e5 [2] 11 c7 [2] 17 f2 [2] 39 f2 [2] 06 ee }

  condition:
    any of them
}