rule TTP_XOR_WriteProcessMemory_25a2 {
  strings:
    $key_25a2 = { 72 d0 [2] 40 f2 [2] 46 c7 [2] 68 c7 [2] 57 db }

  condition:
    any of them
}