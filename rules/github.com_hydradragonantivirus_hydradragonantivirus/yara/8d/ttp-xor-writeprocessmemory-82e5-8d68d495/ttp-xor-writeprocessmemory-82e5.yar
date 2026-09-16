rule TTP_XOR_WriteProcessMemory_82e5 {
  strings:
    $key_82e5 = { d5 97 [2] e7 b5 [2] e1 80 [2] cf 80 [2] f0 9c }

  condition:
    any of them
}