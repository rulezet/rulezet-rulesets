rule TTP_XOR_WriteProcessMemory_8fe9 {
  strings:
    $key_8fe9 = { d8 9b [2] ea b9 [2] ec 8c [2] c2 8c [2] fd 90 }

  condition:
    any of them
}