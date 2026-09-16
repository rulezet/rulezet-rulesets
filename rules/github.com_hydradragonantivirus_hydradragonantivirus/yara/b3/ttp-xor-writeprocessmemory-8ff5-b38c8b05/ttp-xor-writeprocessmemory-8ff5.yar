rule TTP_XOR_WriteProcessMemory_8ff5 {
  strings:
    $key_8ff5 = { d8 87 [2] ea a5 [2] ec 90 [2] c2 90 [2] fd 8c }

  condition:
    any of them
}