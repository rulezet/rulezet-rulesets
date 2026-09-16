rule TTP_XOR_WriteProcessMemory_14d5 {
  strings:
    $key_14d5 = { 43 a7 [2] 71 85 [2] 77 b0 [2] 59 b0 [2] 66 ac }

  condition:
    any of them
}