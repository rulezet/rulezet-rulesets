rule TTP_XOR_WriteProcessMemory_d193 {
  strings:
    $key_d193 = { 86 e1 [2] b4 c3 [2] b2 f6 [2] 9c f6 [2] a3 ea }

  condition:
    any of them
}