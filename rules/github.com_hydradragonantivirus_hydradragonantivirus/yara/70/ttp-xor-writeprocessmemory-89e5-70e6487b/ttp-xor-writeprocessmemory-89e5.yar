rule TTP_XOR_WriteProcessMemory_89e5 {
  strings:
    $key_89e5 = { de 97 [2] ec b5 [2] ea 80 [2] c4 80 [2] fb 9c }

  condition:
    any of them
}