rule TTP_XOR_WriteProcessMemory_8693 {
  strings:
    $key_8693 = { d1 e1 [2] e3 c3 [2] e5 f6 [2] cb f6 [2] f4 ea }

  condition:
    any of them
}