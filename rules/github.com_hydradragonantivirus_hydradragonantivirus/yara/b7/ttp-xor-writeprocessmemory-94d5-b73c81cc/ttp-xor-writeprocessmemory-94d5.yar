rule TTP_XOR_WriteProcessMemory_94d5 {
  strings:
    $key_94d5 = { c3 a7 [2] f1 85 [2] f7 b0 [2] d9 b0 [2] e6 ac }

  condition:
    any of them
}