rule TTP_XOR_WriteProcessMemory_1793 {
  strings:
    $key_1793 = { 40 e1 [2] 72 c3 [2] 74 f6 [2] 5a f6 [2] 65 ea }

  condition:
    any of them
}