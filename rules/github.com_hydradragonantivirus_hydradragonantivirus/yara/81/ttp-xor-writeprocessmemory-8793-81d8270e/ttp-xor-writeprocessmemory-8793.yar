rule TTP_XOR_WriteProcessMemory_8793 {
  strings:
    $key_8793 = { d0 e1 [2] e2 c3 [2] e4 f6 [2] ca f6 [2] f5 ea }

  condition:
    any of them
}