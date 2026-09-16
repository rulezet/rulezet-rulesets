rule TTP_XOR_WriteProcessMemory_87f4 {
  strings:
    $key_87f4 = { d0 86 [2] e2 a4 [2] e4 91 [2] ca 91 [2] f5 8d }

  condition:
    any of them
}