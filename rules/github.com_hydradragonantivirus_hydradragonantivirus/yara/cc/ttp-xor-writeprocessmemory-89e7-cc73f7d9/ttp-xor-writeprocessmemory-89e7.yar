rule TTP_XOR_WriteProcessMemory_89e7 {
  strings:
    $key_89e7 = { de 95 [2] ec b7 [2] ea 82 [2] c4 82 [2] fb 9e }

  condition:
    any of them
}