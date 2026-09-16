rule TTP_XOR_WriteProcessMemory_9093 {
  strings:
    $key_9093 = { c7 e1 [2] f5 c3 [2] f3 f6 [2] dd f6 [2] e2 ea }

  condition:
    any of them
}