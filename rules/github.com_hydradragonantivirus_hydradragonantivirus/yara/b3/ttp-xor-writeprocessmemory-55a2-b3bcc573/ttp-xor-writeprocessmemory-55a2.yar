rule TTP_XOR_WriteProcessMemory_55a2 {
  strings:
    $key_55a2 = { 02 d0 [2] 30 f2 [2] 36 c7 [2] 18 c7 [2] 27 db }

  condition:
    any of them
}