rule TTP_XOR_WriteProcessMemory_8fd2 {
  strings:
    $key_8fd2 = { d8 a0 [2] ea 82 [2] ec b7 [2] c2 b7 [2] fd ab }

  condition:
    any of them
}