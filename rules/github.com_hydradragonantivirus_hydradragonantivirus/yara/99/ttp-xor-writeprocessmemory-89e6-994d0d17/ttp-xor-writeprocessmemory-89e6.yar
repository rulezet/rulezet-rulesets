rule TTP_XOR_WriteProcessMemory_89e6 {
  strings:
    $key_89e6 = { de 94 [2] ec b6 [2] ea 83 [2] c4 83 [2] fb 9f }

  condition:
    any of them
}