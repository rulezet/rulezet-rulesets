rule TTP_XOR_WriteProcessMemory_8625 {
  strings:
    $key_8625 = { d1 57 [2] e3 75 [2] e5 40 [2] cb 40 [2] f4 5c }

  condition:
    any of them
}