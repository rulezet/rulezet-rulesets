rule TTP_XOR_WriteProcessMemory_26a2 {
  strings:
    $key_26a2 = { 71 d0 [2] 43 f2 [2] 45 c7 [2] 6b c7 [2] 54 db }

  condition:
    any of them
}