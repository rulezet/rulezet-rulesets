rule TTP_XOR_WriteProcessMemory_8fd7 {
  strings:
    $key_8fd7 = { d8 a5 [2] ea 87 [2] ec b2 [2] c2 b2 [2] fd ae }

  condition:
    any of them
}