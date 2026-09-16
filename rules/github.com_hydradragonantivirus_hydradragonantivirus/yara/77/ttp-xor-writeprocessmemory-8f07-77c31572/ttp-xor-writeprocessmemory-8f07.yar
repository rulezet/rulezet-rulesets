rule TTP_XOR_WriteProcessMemory_8f07 {
  strings:
    $key_8f07 = { d8 75 [2] ea 57 [2] ec 62 [2] c2 62 [2] fd 7e }

  condition:
    any of them
}