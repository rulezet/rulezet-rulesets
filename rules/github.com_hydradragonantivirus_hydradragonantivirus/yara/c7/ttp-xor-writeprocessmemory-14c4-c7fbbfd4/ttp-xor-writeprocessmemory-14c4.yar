rule TTP_XOR_WriteProcessMemory_14c4 {
  strings:
    $key_14c4 = { 43 b6 [2] 71 94 [2] 77 a1 [2] 59 a1 [2] 66 bd }

  condition:
    any of them
}