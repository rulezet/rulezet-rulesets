rule TTP_XOR_WriteProcessMemory_67a2 {
  strings:
    $key_67a2 = { 30 d0 [2] 02 f2 [2] 04 c7 [2] 2a c7 [2] 15 db }

  condition:
    any of them
}