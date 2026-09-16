rule TTP_XOR_WriteProcessMemory_89e9 {
  strings:
    $key_89e9 = { de 9b [2] ec b9 [2] ea 8c [2] c4 8c [2] fb 90 }

  condition:
    any of them
}