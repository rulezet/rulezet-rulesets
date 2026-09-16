rule TTP_XOR_WriteProcessMemory_8fd0 {
  strings:
    $key_8fd0 = { d8 a2 [2] ea 80 [2] ec b5 [2] c2 b5 [2] fd a9 }

  condition:
    any of them
}