rule TTP_XOR_WriteProcessMemory_61a2 {
  strings:
    $key_61a2 = { 36 d0 [2] 04 f2 [2] 02 c7 [2] 2c c7 [2] 13 db }

  condition:
    any of them
}