rule TTP_XOR_WriteProcessMemory_c530 {
  strings:
    $key_c530 = { 92 42 [2] a0 60 [2] a6 55 [2] 88 55 [2] b7 49 }

  condition:
    any of them
}