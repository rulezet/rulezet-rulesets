rule TTP_XOR_WriteProcessMemory_8fc5 {
  strings:
    $key_8fc5 = { d8 b7 [2] ea 95 [2] ec a0 [2] c2 a0 [2] fd bc }

  condition:
    any of them
}