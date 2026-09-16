rule TTP_XOR_WriteProcessMemory_5193 {
  strings:
    $key_5193 = { 06 e1 [2] 34 c3 [2] 32 f6 [2] 1c f6 [2] 23 ea }

  condition:
    any of them
}