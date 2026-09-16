rule TTP_XOR_WriteProcessMemory_89e2 {
  strings:
    $key_89e2 = { de 90 [2] ec b2 [2] ea 87 [2] c4 87 [2] fb 9b }

  condition:
    any of them
}