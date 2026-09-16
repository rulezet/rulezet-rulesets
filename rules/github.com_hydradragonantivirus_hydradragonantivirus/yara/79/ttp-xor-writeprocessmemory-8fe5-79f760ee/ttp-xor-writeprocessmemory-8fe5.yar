rule TTP_XOR_WriteProcessMemory_8fe5 {
  strings:
    $key_8fe5 = { d8 97 [2] ea b5 [2] ec 80 [2] c2 80 [2] fd 9c }

  condition:
    any of them
}