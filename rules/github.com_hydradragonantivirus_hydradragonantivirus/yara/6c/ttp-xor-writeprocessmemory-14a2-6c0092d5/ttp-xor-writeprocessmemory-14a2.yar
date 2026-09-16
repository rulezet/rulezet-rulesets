rule TTP_XOR_WriteProcessMemory_14a2 {
  strings:
    $key_14a2 = { 43 d0 [2] 71 f2 [2] 77 c7 [2] 59 c7 [2] 66 db }

  condition:
    any of them
}