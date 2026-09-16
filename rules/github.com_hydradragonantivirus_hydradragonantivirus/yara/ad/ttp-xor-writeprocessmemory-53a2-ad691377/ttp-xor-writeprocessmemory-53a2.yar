rule TTP_XOR_WriteProcessMemory_53a2 {
  strings:
    $key_53a2 = { 04 d0 [2] 36 f2 [2] 30 c7 [2] 1e c7 [2] 21 db }

  condition:
    any of them
}