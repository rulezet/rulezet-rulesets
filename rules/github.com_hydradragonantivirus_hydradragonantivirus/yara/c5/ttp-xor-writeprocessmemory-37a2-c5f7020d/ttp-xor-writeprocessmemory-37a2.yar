rule TTP_XOR_WriteProcessMemory_37a2 {
  strings:
    $key_37a2 = { 60 d0 [2] 52 f2 [2] 54 c7 [2] 7a c7 [2] 45 db }

  condition:
    any of them
}