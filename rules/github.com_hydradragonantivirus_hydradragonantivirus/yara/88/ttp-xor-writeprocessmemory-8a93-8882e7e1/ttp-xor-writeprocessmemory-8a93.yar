rule TTP_XOR_WriteProcessMemory_8a93 {
  strings:
    $key_8a93 = { dd e1 [2] ef c3 [2] e9 f6 [2] c7 f6 [2] f8 ea }

  condition:
    any of them
}