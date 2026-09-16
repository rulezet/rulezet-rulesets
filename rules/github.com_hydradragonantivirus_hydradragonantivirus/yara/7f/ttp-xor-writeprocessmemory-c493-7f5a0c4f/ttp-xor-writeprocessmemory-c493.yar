rule TTP_XOR_WriteProcessMemory_c493 {
  strings:
    $key_c493 = { 93 e1 [2] a1 c3 [2] a7 f6 [2] 89 f6 [2] b6 ea }

  condition:
    any of them
}