rule TTP_XOR_WriteProcessMemory_8fd5 {
  strings:
    $key_8fd5 = { d8 a7 [2] ea 85 [2] ec b0 [2] c2 b0 [2] fd ac }

  condition:
    any of them
}