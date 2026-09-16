rule TTP_XOR_WriteProcessMemory_8fd4 {
  strings:
    $key_8fd4 = { d8 a6 [2] ea 84 [2] ec b1 [2] c2 b1 [2] fd ad }

  condition:
    any of them
}