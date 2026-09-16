rule TTP_XOR_WriteProcessMemory_3793 {
  strings:
    $key_3793 = { 60 e1 [2] 52 c3 [2] 54 f6 [2] 7a f6 [2] 45 ea }

  condition:
    any of them
}