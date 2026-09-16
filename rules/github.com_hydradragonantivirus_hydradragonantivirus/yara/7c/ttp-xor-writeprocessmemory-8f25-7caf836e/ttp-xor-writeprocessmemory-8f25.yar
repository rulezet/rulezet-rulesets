rule TTP_XOR_WriteProcessMemory_8f25 {
  strings:
    $key_8f25 = { d8 57 [2] ea 75 [2] ec 40 [2] c2 40 [2] fd 5c }

  condition:
    any of them
}