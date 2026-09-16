rule TTP_XOR_WriteProcessMemory_00a2 {
  strings:
    $key_00a2 = { 57 d0 [2] 65 f2 [2] 63 c7 [2] 4d c7 [2] 72 db }

  condition:
    any of them
}