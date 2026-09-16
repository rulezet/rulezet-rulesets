rule TTP_XOR_WriteProcessMemory_8fd3 {
  strings:
    $key_8fd3 = { d8 a1 [2] ea 83 [2] ec b6 [2] c2 b6 [2] fd aa }

  condition:
    any of them
}