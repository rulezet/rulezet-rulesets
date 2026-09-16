rule TTP_XOR_WriteProcessMemory_89e1 {
  strings:
    $key_89e1 = { de 93 [2] ec b1 [2] ea 84 [2] c4 84 [2] fb 98 }

  condition:
    any of them
}