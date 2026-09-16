rule TTP_XOR_WriteProcessMemory_8ff0 {
  strings:
    $key_8ff0 = { d8 82 [2] ea a0 [2] ec 95 [2] c2 95 [2] fd 89 }

  condition:
    any of them
}