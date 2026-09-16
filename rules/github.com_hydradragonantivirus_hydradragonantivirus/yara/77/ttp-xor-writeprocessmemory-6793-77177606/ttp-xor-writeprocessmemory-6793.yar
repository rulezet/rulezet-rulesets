rule TTP_XOR_WriteProcessMemory_6793 {
  strings:
    $key_6793 = { 30 e1 [2] 02 c3 [2] 04 f6 [2] 2a f6 [2] 15 ea }

  condition:
    any of them
}