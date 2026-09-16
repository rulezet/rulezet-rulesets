rule TTP_XOR_WriteProcessMemory_82f5 {
  strings:
    $key_82f5 = { d5 87 [2] e7 a5 [2] e1 90 [2] cf 90 [2] f0 8c }

  condition:
    any of them
}