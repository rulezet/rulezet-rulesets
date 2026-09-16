rule TTP_XOR_WriteProcessMemory_1422 {
  strings:
    $key_1422 = { 43 50 [2] 71 72 [2] 77 47 [2] 59 47 [2] 66 5b }

  condition:
    any of them
}