rule TTP_XOR_WriteProcessMemory_8fd6 {
  strings:
    $key_8fd6 = { d8 a4 [2] ea 86 [2] ec b3 [2] c2 b3 [2] fd af }

  condition:
    any of them
}