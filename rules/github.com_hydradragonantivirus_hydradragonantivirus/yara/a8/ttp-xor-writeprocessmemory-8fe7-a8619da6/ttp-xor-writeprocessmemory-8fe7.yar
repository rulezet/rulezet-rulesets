rule TTP_XOR_WriteProcessMemory_8fe7 {
  strings:
    $key_8fe7 = { d8 95 [2] ea b7 [2] ec 82 [2] c2 82 [2] fd 9e }

  condition:
    any of them
}